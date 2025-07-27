package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
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
	id       string
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
			id:       fmt.Sprintf("worker #%d", i),
			server:   server,
			requests: make(chan *DNSRequest, config.Server.WorkerChannelBufferSize),
		}
	}

	return server, nil
}

// Start begins listening for DNS queries
func (s *DNSServer) Start(ctx context.Context) error {
	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", s.config.Server.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Start listening
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}

	logging.Info("UDP server started",
		"address", s.config.Server.GetAddress(),
		"workers", s.config.Server.MaxWorkers)

	// Start worker goroutines
	for i := range s.workers {
		s.wg.Add(1)
		go s.workers[i].run()
	}

	// Start accepting connections
	s.wg.Add(1)
	s.acceptLoop(ctx)

	return nil
}

// acceptLoop handles incoming UDP packets
func (s *DNSServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	buffer := make([]byte, s.config.Server.MaxPacketSize)

	for {
		select {
		case <-ctx.Done():
			logging.Info("Accept loop stopping due to context cancellation")
			return
		case <-s.shutdown:
			logging.Info("Accept loop stopping due to shutdown signal")
			return
		default:
			// Set read timeout
			readTimeout := time.Duration(s.config.Server.ReadTimeout)

			err := s.conn.SetReadDeadline(time.Now().Add(readTimeout))
			if err != nil {
				logging.Warn("SetReadDeadline failed",
					"message", "failed to set read deadline",
					"file", logging.GetCallerLocation(),
				)
			}

			// Read packet
			n, clientAddr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				// Check if it's a timeout (expected during shutdown)
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				logging.Error("Failed to read UDP packet", "error", err)
				continue
			}

			// Create request
			request := &DNSRequest{
				Data:       make([]byte, n),
				ClientAddr: clientAddr,
				ReceivedAt: time.Now(),
			}

			// copy data from packet to internal buffer
			copy(request.Data, buffer[:n])

			// Log the incoming request
			logging.Debug("Received DNS query",
				"client", clientAddr.String(),
				"size", n,
				"data_preview", fmt.Sprintf("%x", request.Data[:min(n, 16)]))

			// Distribute to workers using round-robin
			workerIndex := len(request.Data) % len(s.workers)
			select {
			case s.workers[workerIndex].requests <- request:
				// Request queued successfully
			default:
				// Worker queue is full, log and drop
				logging.Warn("Worker queue full, dropping request",
					"worker_id", workerIndex,
					"client", clientAddr.String())
			}
		}
	}
}

// worker.run processes DNS requests
func (w *worker) run() {
	defer w.server.wg.Done()

	logging.Debug("Worker started", "worker_id", w.id)

	for {
		select {
		case <-w.server.shutdown:
			logging.Debug("Worker stopping", "worker_id", w.id)
			return

		case request := <-w.requests:
			w.processRequest(request)
		}
	}
}

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

	// TODO: Parse packet, process query, send response

}

// Shutdown gracefully stops the DNS server
func (s *DNSServer) Shutdown(ctx context.Context) error {
	logging.Info("Shutting down DNS server...")

	// Signal shutdown
	close(s.shutdown)

	// Close UDP connection
	if s.conn != nil {
		s.conn.Close()
	}

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logging.Info("DNS server shutdown complete")
		return nil
	case <-ctx.Done():
		logging.Warn("DNS server shutdown timed out")
		return ctx.Err()
	}
}

// Helper function for Go versions that don't have min()
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
