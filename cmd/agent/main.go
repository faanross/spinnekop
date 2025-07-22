package main

import (
	"errors"
	"fmt"
	"github.com/faanross/spinnekop/internal/crafter"
	"github.com/faanross/spinnekop/internal/models"
	"github.com/faanross/spinnekop/internal/validate"
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

	// fmt.Println(string(yamlFile))

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
		fmt.Println("✅ DNS request configuration is valid!")
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

	// (6) Print results and visualize final packet
	// We unpack it back into dns.Msg structure
	var finalMsg dns.Msg
	err = finalMsg.Unpack(packedMsg)
	if err != nil {
		fmt.Printf("Error unpacking modified message: %v\n", err)
		return
	}

	// The library's String() method won't show the Z flag, but this confirms the packet is valid.
	fmt.Println("\n--- Final DNS Message (After Override) ---")
	fmt.Println(finalMsg.String())
	fmt.Printf("NOTE: Z flag was set to %d in the raw packet bytes.\n", dnsRequest.Header.Z)
	fmt.Println("------------------------------------------")

}
