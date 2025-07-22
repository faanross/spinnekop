package visualizer

import "github.com/fatih/color"

const (
	// bytesPerRow defines how many bytes to show per line in the hex dump.
	bytesPerRow = 16
)

// VisualizePacket prints a DNS packet in a user-friendly hex and ASCII format.
func VisualizePacket(packet []byte) {

	color.Cyan("->>> DNS REQUEST PACKET VISUALIZATION <<<- ")

}
