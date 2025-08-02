package server

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/parser"
	"github.com/faanross/spinnekop/internal/visualizer"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

// processRequest represents a single worker handling a single DNS request
func (w *worker) processRequest(request *DNSRequest) {
	startTime := time.Now()

	logging.Info("Processing DNS request",
		"worker_id", w.id,
		"client", request.ClientAddr.String(),
		"packet_size", len(request.Data))

	logging.Debug("DNS packet received",
		"worker_id", w.id,
		"processing_time", time.Since(startTime),
		"packet_hex", fmt.Sprintf("%x", request.Data))

	// use visualizer for ASCII and HEX representation
	visualizer.VisualizePacket(request.Data)

	// parse packet
	dnsParser := parser.NewDNSParser(w.server.config)
	parsed := dnsParser.ParsePacket(request.Data, request.ClientAddr.String())

	// Log detailed analysis for interesting packets
	if !parsed.Valid || len(parsed.Analysis.Issues) > 0 || len(parsed.Analysis.Warnings) > 0 {
		logging.Warn("Packet analysis found issues",
			"worker_id", w.id,
			"valid", parsed.Valid,
			"issues", parsed.Analysis.Issues,
			"warnings", parsed.Analysis.Warnings)
	}

	// Log query details if it's a valid query
	if parsed.Valid && parsed.Question != nil {
		logging.Info("DNS Query details",
			"worker_id", w.id,
			"domain", parsed.Question.Name,
			"type", parsed.Question.QtypeString,
			"class", parsed.Question.QclassString,
			"authoritative", parsed.Analysis.SupportedByServer)
	}

	// Build and send the response if the query is valid
	if parsed.Valid && parsed.Question != nil {
		w.buildAndSendResponse(parsed, request.ClientAddr)
	}

}

// buildAndSendResponse constructs and sends a DNS response.
func (w *worker) buildAndSendResponse(parsedRequest *parser.ParsedPacket, clientAddr *net.UDPAddr) {
	// 1. Create a new response message based on the request.
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(parsedRequest.Message)

	// 2. Check if we are authoritative for the requested domain.
	zone := w.server.config.FindZone(parsedRequest.Question.Name)
	if zone != nil {
		// We are authoritative! Set the Authoritative Answer (AA) flag.
		responseMsg.Authoritative = true

		// As per our config, refuse recursion if requested.
		if w.server.config.Security.ResponsePolicies.RefuseRecursion {
			responseMsg.RecursionAvailable = false
		}

		// 3. Find the corresponding records in our zone file.
		// This is a simplified example for 'A' records.
		switch parsedRequest.Question.Qtype {
		case dns.TypeA:
			for _, aRecord := range zone.ARecords {
				// Check for exact match
				if aRecord.Name == parsedRequest.Question.Name {
					rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", aRecord.Name, aRecord.TTL, aRecord.IP))
					if err == nil {
						responseMsg.Answer = append(responseMsg.Answer, rr)
					}
				} else if strings.HasPrefix(aRecord.Name, "*.") {
					// Handle wildcard
					wildcardBase := strings.TrimPrefix(aRecord.Name, "*.")
					if strings.HasSuffix(parsedRequest.Question.Name, wildcardBase) {
						// Create response with the queried name
						rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", parsedRequest.Question.Name, aRecord.TTL, aRecord.IP))
						if err == nil {
							responseMsg.Answer = append(responseMsg.Answer, rr)
						}
					}
				}
			}
			// You can add more cases here for AAAA, CNAME, MX, etc.
		}

		// 4. If we found a zone but no records, it's an NXDOMAIN (Name Error).
		if len(responseMsg.Answer) == 0 {
			responseMsg.Rcode = dns.RcodeNameError
		}

	} else {
		// 5. If we're not authoritative for the domain, we refuse the query.
		responseMsg.Rcode = dns.RcodeRefused
	}

	// 6. Pack the response message into bytes.
	responseBytes, err := responseMsg.Pack()
	if err != nil {
		logging.Error("Failed to pack DNS response", "error", err)
		return
	}

	// 7. Manually set the Z-value
	if err := w.setServerZValue(responseBytes); err != nil {
		logging.Error("Failed to set Z value", "error", err)
		return
	}

	// 8. Send the response back to the client.
	_, err = w.server.conn.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		logging.Error("Failed to send DNS response", "error", err)
	} else {
		logging.Info("Sent DNS response",
			"client", clientAddr.String(),
			"rcode", dns.RcodeToString[responseMsg.Rcode])
	}
}

// setServerZValue manually sets the Z flag value in a packed DNS response
func (w *worker) setServerZValue(packedMsg []byte) error {
	// Get current Z value from simulation
	zValue := w.server.getCurrentZValue()

	// The DNS header is 12 bytes long
	if len(packedMsg) < 12 {
		return fmt.Errorf("packed message too short: %d bytes", len(packedMsg))
	}

	// Read current flags (bytes 2-3)
	flags := uint16(packedMsg[2])<<8 | uint16(packedMsg[3])

	// Clear existing Z bits (mask: 1111 1111 1000 1111 = 0xFF8F)
	flags &= 0xFF8F

	// Set new Z value (shift left by 4 to align with position)
	flags |= uint16(zValue) << 4

	// Write modified flags back
	packedMsg[2] = byte(flags >> 8)
	packedMsg[3] = byte(flags)

	return nil
}
