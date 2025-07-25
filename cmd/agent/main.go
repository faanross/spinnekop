package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/crafter"
	"github.com/faanross/spinnekop/internal/network"
	"github.com/faanross/spinnekop/internal/utils"
	"github.com/faanross/spinnekop/internal/visualizer"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

func main() {

	// Load our config from config.go
	dnsRequest := getEmbeddedAgentConfig()

	// Create our dns.Msg structure (miekg/dns)
	dnsMsg, err := crafter.BuildDNSRequest(dnsRequest)
	if err != nil {
		fmt.Printf("Error building DNS request using miekg: %v\n", err)
		return
	}

	// Pack the dns.Msg to convert to byte slice
	packedMsg, err := dnsMsg.Pack()
	if err != nil {
		fmt.Printf("Error packing message: %v\n", err)
		return
	}

	// Now we can apply our manual override for the Z flag
	err = crafter.ApplyManualOverride(packedMsg, dnsRequest.Header)
	if err != nil {
		fmt.Printf("Error applying manual overrides: %v\n", err)
		return
	}

	// Visualize our packet to terminal
	visualizer.VisualizePacket(packedMsg)

	// Determine the final resolver to use based on the YAML config.
	finalResolver, err := utils.DetermineResolver(dnsRequest.Resolver)
	if err != nil {
		fmt.Printf("Error determining resolver: %v\n", err)
		return
	}

	// Send Packet and Receive Response
	responseBytes, err := network.SendAndReceivePacket(packedMsg, finalResolver)
	if err != nil {
		fmt.Printf("\nError during network communication: %v\n", err)
		return
	}

	// Process and Display the Response

	color.Green("\n--- DNS Server Response ---")
	var responseMsg dns.Msg
	err = responseMsg.Unpack(responseBytes)
	if err != nil {
		fmt.Printf("Error unpacking response packet: %v\n", err)
		// Even if unpacking fails, visualize raw bytes
		visualizer.VisualizePacket(responseBytes)
		return
	}

	// Print the parsed, human-readable response.
	fmt.Println(responseMsg.String())

	// And visualize the raw response packet.
	visualizer.VisualizePacket(responseBytes)

}
