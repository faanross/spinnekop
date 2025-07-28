package parser

import (
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"github.com/miekg/dns"
	"time"
)

// ParsedPacket represents a fully analyzed DNS packet
type ParsedPacket struct {
	// Raw data and metadata
	RawData    []byte
	Size       int
	ReceivedAt time.Time
	ClientAddr string

	// Parsed DNS message
	Message *dns.Msg
	Valid   bool
	Error   error

	// Detailed analysis
	Header   *HeaderAnalysis
	Question *QuestionAnalysis
	Analysis *PacketAnalysis
}

// HeaderAnalysis provides detailed header field analysis
type HeaderAnalysis struct {
	ID              uint16
	QR              bool
	QRString        string
	Opcode          int
	OpcodeString    string
	AA              bool
	TC              bool
	RD              bool
	RA              bool
	Z               uint8
	Rcode           int
	RcodeString     string
	QuestionCount   uint16
	AnswerCount     uint16
	AuthorityCount  uint16
	AdditionalCount uint16

	// Analysis flags
	IsQuery            bool
	IsResponse         bool
	IsStandardQuery    bool
	HasNonZeroZ        bool
	IsRecursionDesired bool
}

// QuestionAnalysis provides detailed question section analysis
type QuestionAnalysis struct {
	Name         string
	Qtype        uint16
	QtypeString  string
	Qclass       uint16
	QclassString string

	// Analysis
	IsValidDomain bool
	IsFQDN        bool
	DomainLabels  []string
	IsWildcard    bool
}

// PacketAnalysis provides high-level packet analysis
type PacketAnalysis struct {
	PacketType        string
	IsWellFormed      bool
	IsStandard        bool
	HasEdns           bool
	SupportedByServer bool
	Issues            []string
	Warnings          []string
}

// DNSParser handles DNS packet parsing and analysis
type DNSParser struct {
	Config *srv_models.Config
}
