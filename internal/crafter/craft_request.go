package crafter

import (
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

}
