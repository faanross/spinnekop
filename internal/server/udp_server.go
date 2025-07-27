package server

import (
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"net"
	"sync"
	"time"
)

// DNSServer represents the main DNS server
type DNSServer struct {
	config   *srv_models.Config
	conn     *net.UDPConn
	workers  []worker
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// worker represents a goroutine that processes DNS queries
// the amount can be set in ServerConfig.MaxWorkers
type worker struct {
	id       int
	server   *DNSServer
	requests chan *DNSRequest
}

// DNSRequest represents an incoming DNS query
type DNSRequest struct {
	Data       []byte
	ClientAddr *net.UDPAddr
	ReceivedAt time.Time
}

// NewDNSServer is our DNSServer constructor
func NewDNSServer(config *srv_models.Config) (*DNSServer, error) {
	server := &DNSServer{
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Create worker pool
	server.workers = make([]worker, config.Server.MaxWorkers)
	for i := 0; i < config.Server.MaxWorkers; i++ {
		server.workers[i] = worker{
			id:       i,
			server:   server,
			requests: make(chan *DNSRequest, config.Server.WorkerChannelBufferSize),
		}
	}

	return server, nil
}
