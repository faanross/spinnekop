package crafter

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/models"
	"github.com/miekg/dns"
	"math/rand"
	"time"
)

// BuildDNSRequest takes the parsed request data and translates it into a dns.Msg object.
// It returns a pointer to a dns.Msg and an error if any values are invalid.
func BuildDNSRequest(req models.DNSRequest) (*dns.Msg, error) {

	msg := new(dns.Msg)

	// Header.ID is taken from YAML, OR, if set to 0, we'll generate it randomly

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if req.Header.ID == 0 {
		msg.Id = uint16(r.Intn(65536))
	} else {
		msg.Id = req.Header.ID
	}

	// For the following 3 fields we first want to use our maps in package models
	// To convert their struct field values to those found in miekg package

	opCode, ok := models.OpCodeMap[req.Header.OpCode]
	if !ok {
		return nil, fmt.Errorf("invalid opcode: %s", req.Header.OpCode)
	}
	msg.Opcode = opCode

	qType, ok := models.QTypeMap[req.Question.Type]
	if !ok {
		return nil, fmt.Errorf("invalid question type: %s", req.Question.Type)
	}

	// special condition for qClass since we allow for standard and non-standard values
	var qClass uint16
	if req.Question.StdClass {
		// Standard class mode - look up in map
		var ok bool
		qClass, ok = models.QClassMap[req.Question.Class]
		if !ok {
			return nil, fmt.Errorf("invalid question class: %s", req.Question.Class)
		}
	} else {
		// Custom class mode - use the raw value
		qClass = req.Question.CustomClass
	}

	// For all the remaining fields we can directly use the struct field values

	msg.Response = req.Header.QR

	msg.Authoritative = req.Header.Authoritative
	msg.Truncated = req.Header.Truncated
	msg.RecursionDesired = req.Header.RecursionDesired
	msg.RecursionAvailable = req.Header.RecursionAvailable

	msg.Rcode = int(req.Header.RCode)

	// Reminder: Z-Value cannot be created using miekg/dns,
	// We'll do it manually using ApplyManualOverrides()

	// Manually create the Question struct and append it to the message.
	// This gives us full control and avoids the problematic SetQuestion helper.
	msg.Question = []dns.Question{
		{
			Name:   dns.Fqdn(req.Question.Name),
			Qtype:  qType,
			Qclass: qClass,
		},
	}

	// Add answer records if this is a response
	if req.Header.QR {
		for _, answer := range req.Answers {
			switch answer.Type {
			case "TXT":
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(answer.Name),
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    answer.TTL,
					},
					Txt: []string{answer.Data},
				}
				msg.Answer = append(msg.Answer, rr)
				// Add other record types as needed
			}
		}
	}

	return msg, nil
}
