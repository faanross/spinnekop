package network

import "github.com/faanross/spinnekop/internal/models"

// SendAndReceivePacket sends a raw DNS packet to a
// resolver over UDP and handles the response.

func SendAndReceivePacket(packet []byte, resolver models.Resolver) ([]byte, error) {
}
