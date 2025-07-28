package parser

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"github.com/miekg/dns"
	"time"
)

// NewDNSParser creates a new DNS packet parser
func NewDNSParser(config *srv_models.Config) *DNSParser {
	return &DNSParser{
		Config: config,
	}
}

// ParsePacket performs complete DNS packet analysis (highest-level)
func (p *DNSParser) ParsePacket(rawData []byte, clientAddr string) *ParsedPacket {
	result := &ParsedPacket{
		RawData:    rawData,
		Size:       len(rawData),
		ReceivedAt: time.Now(),
		ClientAddr: clientAddr,
	}

	// Step 1: Parse with miekg/dns library
	msg := new(dns.Msg)

	// Unpack() takes []byte -> dns.Msg
	err := msg.Unpack(rawData)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Errorf("DNS packet parsing failed: %w", err)
		result.Analysis = &PacketAnalysis{
			PacketType:   "MALFORMED",
			IsWellFormed: false,
			Issues:       []string{err.Error()},
		}
		return result
	}

	result.Message = msg
	result.Valid = true

	// Step 2: Analyze header (+ does basic analysis on type, "normalcy" etc.)
	result.Header = p.analyzeHeader(msg)

	// Step 3: Analyze question (if present)
	if len(msg.Question) > 0 {
		result.Question = p.analyzeQuestion(msg.Question[0])
	}

	// Step 4: Perform high-level analysis
	result.Analysis = p.analyzePacket(msg, result.Header, result.Question)

	return result
}

// analyzeHeader provides detailed header analysis
func (p *DNSParser) analyzeHeader(msg *dns.Msg) *HeaderAnalysis {

	// these values all have library objects in miekg/dns (all except z)
	analysis := &HeaderAnalysis{
		ID:              msg.Id,
		QR:              msg.Response,
		Opcode:          msg.Opcode,
		AA:              msg.Authoritative,
		TC:              msg.Truncated,
		RD:              msg.RecursionDesired,
		RA:              msg.RecursionAvailable,
		Rcode:           msg.Rcode,
		QuestionCount:   uint16(len(msg.Question)),
		AnswerCount:     uint16(len(msg.Answer)),
		AuthorityCount:  uint16(len(msg.Ns)),
		AdditionalCount: uint16(len(msg.Extra)),
	}

	// Extract Z flag from raw header since miekg/dns doesn't expose it
	if len(p.getRawHeader()) >= 4 {
		// Z flag is bits 4-6 of the flags field
		flags := uint16(p.getRawHeader()[2])<<8 | uint16(p.getRawHeader()[3])
		analysis.Z = uint8((flags >> 4) & 0x07)
	}

	// String representations
	analysis.QRString = p.qrToString(analysis.QR)
	analysis.OpcodeString = p.opcodeToString(analysis.Opcode)
	analysis.RcodeString = p.rcodeToString(analysis.Rcode)

	// Analysis flags
	analysis.IsQuery = !analysis.QR
	analysis.IsResponse = analysis.QR
	analysis.IsStandardQuery = analysis.Opcode == dns.OpcodeQuery
	analysis.HasNonZeroZ = analysis.Z != 0
	analysis.IsRecursionDesired = analysis.RD

	return analysis
}

// analyzeQuestion provides detailed question analysis
func (p *DNSParser) analyzeQuestion(q dns.Question) *QuestionAnalysis {
	analysis := &QuestionAnalysis{
		Name:         q.Name,
		Qtype:        q.Qtype,
		QtypeString:  dns.TypeToString[q.Qtype],
		Qclass:       q.Qclass,
		QclassString: dns.ClassToString[q.Qclass],
	}

	// Domain analysis
	analysis.IsValidDomain = p.isValidDomainName(analysis.Name)
	analysis.IsFQDN = dns.IsFqdn(analysis.Name)
	analysis.DomainLabels = dns.SplitDomainName(analysis.Name)
	analysis.IsWildcard = len(analysis.DomainLabels) > 0 && analysis.DomainLabels[0] == "*"

	return analysis
}

// analyzePacket performs high-level packet analysis
func (p *DNSParser) analyzePacket(msg *dns.Msg, header *HeaderAnalysis, question *QuestionAnalysis) *PacketAnalysis {
	analysis := &PacketAnalysis{
		IsWellFormed: true,
		IsStandard:   true,
		Issues:       []string{},
		Warnings:     []string{},
	}

	// Determine packet type
	if header.IsQuery {
		if header.IsStandardQuery {
			analysis.PacketType = "STANDARD_QUERY"
		} else {
			analysis.PacketType = fmt.Sprintf("QUERY_OPCODE_%d", header.Opcode)
		}
	} else {
		analysis.PacketType = "RESPONSE"
	}

	// Check for standard compliance issues
	if header.HasNonZeroZ {
		analysis.IsStandard = false
		analysis.Warnings = append(analysis.Warnings,
			fmt.Sprintf("Non-zero Z flag: %d (RFC 1035 requires 0)", header.Z))
	}

	if header.IsQuery && header.RA {
		analysis.Warnings = append(analysis.Warnings,
			"RA flag set in query (should only be set by servers)")
	}

	if header.IsQuery && header.AA {
		analysis.Warnings = append(analysis.Warnings,
			"AA flag set in query (should only be set in authoritative responses)")
	}

	// Check EDNS support
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			analysis.HasEdns = true
			break
		}
	}

	// Check if server supports this query
	if question != nil {
		zone := p.config.FindZone(question.Name)
		analysis.SupportedByServer = zone != nil

		if !analysis.SupportedByServer {
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("Server is not authoritative for domain: %s", question.Name))
		}

		// Check query type support
		if !p.isSupportedQueryType(question.Qtype) {
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("Unsupported query type: %s", question.QtypeString))
		}
	}

	return analysis
}
