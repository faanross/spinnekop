package parser

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

func (p *DNSParser) qrToString(qr bool) string {
	if qr {
		return "RESPONSE"
	}
	return "QUERY"
}

func (p *DNSParser) opcodeToString(opcode int) string {
	opcodes := map[int]string{
		dns.OpcodeQuery:    "QUERY",
		dns.OpcodeIQuery:   "IQUERY",
		dns.OpcodeStatus:   "STATUS",
		dns.OpcodeNotify:   "NOTIFY",
		dns.OpcodeUpdate:   "UPDATE",
		dns.OpcodeStateful: "STATEFUL",
	}

	if name, ok := opcodes[opcode]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", opcode)
}

func (p *DNSParser) rcodeToString(rcode int) string {
	rcodes := map[int]string{
		dns.RcodeSuccess:        "NOERROR",
		dns.RcodeFormatError:    "FORMERR",
		dns.RcodeServerFailure:  "SERVFAIL",
		dns.RcodeNameError:      "NXDOMAIN",
		dns.RcodeNotImplemented: "NOTIMP",
		dns.RcodeRefused:        "REFUSED",
		dns.RcodeYXDomain:       "YXDOMAIN",
		dns.RcodeYXRrset:        "YXRRSET",
		dns.RcodeNXRrset:        "NXRRSET",
		dns.RcodeNotAuth:        "NOTAUTH",
		dns.RcodeNotZone:        "NOTZONE",
	}

	if name, ok := rcodes[rcode]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", rcode)
}

func (p *DNSParser) isValidDomainName(name string) bool {
	// Basic domain name validation
	if name == "" || name == "." {
		return true // Root domain
	}

	labels := dns.SplitDomainName(name)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Additional validation could be added here
	}

	return len(name) <= 253 // Maximum domain name length
}

func (p *DNSParser) isSupportedQueryType(qtype uint16) bool {
	// Check against configured allowed types
	if len(p.Config.Security.QueryFiltering.AllowedTypes) > 0 {
		qtypeString := dns.TypeToString[qtype]
		for _, allowed := range p.Config.Security.QueryFiltering.AllowedTypes {
			if allowed == qtypeString {
				return true
			}
		}
		return false
	}

	// If no restrictions, support common types
	supportedTypes := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX,
		dns.TypeNS, dns.TypeTXT, dns.TypeSOA, dns.TypePTR,
	}

	for _, supported := range supportedTypes {
		if qtype == supported {
			return true
		}
	}

	return false
}

// PrintAnalysis outputs a detailed human-readable analysis
func (p *ParsedPacket) PrintAnalysis() {
	fmt.Println("=== DNS Packet Analysis ===")
	fmt.Printf("Size: %d bytes\n", p.Size)
	fmt.Printf("Client: %s\n", p.ClientAddr)
	fmt.Printf("Received: %s\n", p.ReceivedAt.Format(time.RFC3339))
	fmt.Printf("Valid: %t\n", p.Valid)

	if !p.Valid {
		fmt.Printf("Error: %v\n", p.Error)
		return
	}

	fmt.Println("\n--- Header Analysis ---")
	h := p.Header
	fmt.Printf("ID: %d (0x%04X)\n", h.ID, h.ID)
	fmt.Printf("QR: %t (%s)\n", h.QR, h.QRString)
	fmt.Printf("Opcode: %d (%s)\n", h.Opcode, h.OpcodeString)
	fmt.Printf("AA: %t (Authoritative Answer)\n", h.AA)
	fmt.Printf("TC: %t (Truncated)\n", h.TC)
	fmt.Printf("RD: %t (Recursion Desired)\n", h.RD)
	fmt.Printf("RA: %t (Recursion Available)\n", h.RA)
	fmt.Printf("Z: %d (Reserved bits)\n", h.Z)
	fmt.Printf("RCODE: %d (%s)\n", h.Rcode, h.RcodeString)
	fmt.Printf("Questions: %d\n", h.QuestionCount)
	fmt.Printf("Answers: %d\n", h.AnswerCount)
	fmt.Printf("Authority: %d\n", h.AuthorityCount)
	fmt.Printf("Additional: %d\n", h.AdditionalCount)

	if p.Question != nil {
		fmt.Println("\n--- Question Analysis ---")
		q := p.Question
		fmt.Printf("Name: %s\n", q.Name)
		fmt.Printf("Type: %d (%s)\n", q.Qtype, q.QtypeString)
		fmt.Printf("Class: %d (%s)\n", q.Qclass, q.QclassString)
		fmt.Printf("FQDN: %t\n", q.IsFQDN)
		fmt.Printf("Valid Domain: %t\n", q.IsValidDomain)
		fmt.Printf("Labels: %v\n", q.DomainLabels)
		if q.IsWildcard {
			fmt.Println("⚠️  Wildcard query detected")
		}
	}

	fmt.Println("\n--- Packet Analysis ---")
	a := p.Analysis
	fmt.Printf("Type: %s\n", a.PacketType)
	fmt.Printf("Well-formed: %t\n", a.IsWellFormed)
	fmt.Printf("RFC Compliant: %t\n", a.IsStandard)
	fmt.Printf("EDNS Support: %t\n", a.HasEdns)
	fmt.Printf("Server Supports: %t\n", a.SupportedByServer)

	if len(a.Issues) > 0 {
		fmt.Println("\n🚨 Issues:")
		for _, issue := range a.Issues {
			fmt.Printf("  • %s\n", issue)
		}
	}

	if len(a.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, warning := range a.Warnings {
			fmt.Printf("  • %s\n", warning)
		}
	}

	fmt.Println("===========================")
}
