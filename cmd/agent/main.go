package main

import (
	"errors"
	"fmt"
	"github.com/faanross/spinnekop/internal/crafter"
	"github.com/faanross/spinnekop/internal/models"
	"github.com/faanross/spinnekop/internal/network"
	"github.com/faanross/spinnekop/internal/utils"
	"github.com/faanross/spinnekop/internal/validate"
	"github.com/faanross/spinnekop/internal/visualizer"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"os"
)

// assume go run from root, otherwise change path
var pathToYamlFile = "./configs/agent.yaml"

func main() {

	// (1) read yaml-file from disk
	yamlFile, err := os.ReadFile(pathToYamlFile)
	if err != nil {
		fmt.Printf("Error reading YAML file: %v\n", err)
		return
	}

	// (2) DNS request struct + unmarshall

	var dnsRequest models.DNSRequest
	err = yaml.Unmarshal(yamlFile, &dnsRequest)
	if err != nil {
		fmt.Printf("Error unmarshalling YAML file: %v\n", err)
		return
	}

	// fmt.Printf("%+v\n", dnsRequest)

	// (3) Validate request fields

	if err := validate.ValidateRequest(&dnsRequest); err != nil {
		// Use a type assertion to check if it's the specific type we're looking for.
		var validationErrs validate.ValidationErrors
		if errors.As(err, &validationErrs) {
			fmt.Println("Configuration is invalid. Errors:")
			for _, validationErr := range validationErrs {
				fmt.Printf("  - %s\n", validationErr)
			}
		}
		return
	} else {
		fmt.Printf("✅ DNS request configuration is valid!\n\n")
	}

	dnsMsg, err := crafter.BuildDNSRequest(dnsRequest)
	if err != nil {
		fmt.Printf("Error building DNS request using miekg: %v\n", err)
		return
	}

	// (4) Pack the dnsMsg to convert to byte slice
	packedMsg, err := dnsMsg.Pack()
	if err != nil {
		fmt.Printf("Error packing message: %v\n", err)
		return
	}

	// (5) Now we can apply our manual override for the Z flag
	err = crafter.ApplyManualOverride(packedMsg, dnsRequest.Header)
	if err != nil {
		fmt.Printf("Error applying manual overrides: %v\n", err)
		return
	}

	// (6) Visualize our packet to terminal
	visualizer.VisualizePacket(packedMsg)

	// (7) Determine the final resolver to use based on the YAML config.
	finalResolver, err := utils.DetermineResolver(dnsRequest.Resolver)
	if err != nil {
		fmt.Printf("Error determining resolver: %v\n", err)
		return
	}

	// (8) Send Packet and Receive Response
	responseBytes, err := network.SendAndReceivePacket(packedMsg, finalResolver)
	if err != nil {
		fmt.Printf("\nError during network communication: %v\n", err)
		return
	}

	// (9) Process and Display the Response

	color.Green("\n--- DNS Server Response ---")
	var responseMsg dns.Msg
	err = responseMsg.Unpack(responseBytes)
	if err != nil {
		fmt.Printf("Error unpacking response packet: %v\n", err)
		// Even if unpacking fails, visualize raw bytes
		visualizer.VisualizePacket(responseBytes)
		return
	}

	// (10) Print the parsed, human-readable response.
	fmt.Println(responseMsg.String())

	// (11) And visualize the raw response packet.
	visualizer.VisualizePacket(responseBytes)

}
