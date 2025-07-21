package validate

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/models"
	"net"
)

func ValidateRequest(dnsRequest *models.DNSRequest) error {
	var validateErrs []error

	// HEADER SECTION VALIDATION

	// make sure Header.OpCode appears in our OpCodeMap
	if _, ok := models.OpCodeMap[dnsRequest.Header.OpCode]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid opcode: %s", dnsRequest.Header.OpCode))
	}

	// make sure Header.Z is not >7 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.Z > 7 {
		validateErrs = append(validateErrs, fmt.Errorf("Z flag must be between 0 and 7, but got %d", dnsRequest.Header.Z))
	}

	// make sure Header.RCode is not >15 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.RCode > 15 {
		validateErrs = append(validateErrs, fmt.Errorf("RCode must be between 0 and 15, but got %d", dnsRequest.Header.RCode))
	}

	if dnsRequest.Header.QuestionCount != 1 {
		validateErrs = append(validateErrs, fmt.Errorf("QuestionCount MUST be 1, but got %d", dnsRequest.Header.QuestionCount))
	}

	if dnsRequest.Header.AnswerCount != 0 {
		validateErrs = append(validateErrs, fmt.Errorf("AnswerCount MUST be 0, but got %d", dnsRequest.Header.AnswerCount))
	}

	if dnsRequest.Header.AuthorityCount != 0 {
		validateErrs = append(validateErrs, fmt.Errorf("AuthorityCount MUST be 0, but got %d", dnsRequest.Header.AuthorityCount))
	}

	// QUESTION SECTION VALIDATION
	if _, ok := models.QTypeMap[dnsRequest.Question.Type]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question type: %s", dnsRequest.Question.Type))
	}

	if _, ok := models.QClassMap[dnsRequest.Question.Class]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question class: %s", dnsRequest.Question.Class))
	}

	// RESOLVER SECTION VALIDATION
	if net.ParseIP(dnsRequest.Resolver.IP) == nil {
		validateErrs = append(validateErrs, fmt.Errorf("resolver IP is not a valid IP address: %s", dnsRequest.Resolver.IP))
	}

	if dnsRequest.Resolver.Port < 1 || dnsRequest.Resolver.Port > 65535 {
		validateErrs = append(validateErrs, fmt.Errorf("resolver port is not a valid port number: %d", dnsRequest.Resolver.Port))
	}

	if len(validateErrs) > 0 {
		return validateErrs
	}

	// Otherwise, return nil for success.
	return nil
}
