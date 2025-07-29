package server

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/parser"
	"github.com/faanross/spinnekop/internal/visualizer"
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

	// TODO  process query, send response

}
