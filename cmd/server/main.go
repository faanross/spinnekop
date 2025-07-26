package main

import (
	"fmt"
)

var configPath = "./configs/server.yaml"

func main() {
	// instantiate ConfigLoader struct
	loader := NewConfigLoader(configPath)

	// read + validate + unmarshall config file
	config, err := loader.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		fmt.Printf("Please create config file and save it as: %s\n", configPath)
	}

	// print loaded config
	loader.PrintConfiguration()

	// perform zone consistency checks
	if err := loader.ValidateZoneConsistency(); err != nil {
		fmt.Printf("Zone consistency check failed: %v\n", err)
		return
	}

	fmt.Println("\nConfiguration loaded and validated successfully!")

	// test zone lookup functionality
	testDomains := []string{
		"timeserversync.com",
		"www.timeserversync.com",
		"api.timeserversync.com",
		"nonexistent.example.com",
	}

	fmt.Println("\nTesting zone lookup:")
	for _, domain := range testDomains {
		zone := config.FindZone(domain)
		if zone != nil {
			fmt.Printf("  %s -> Found in zone: %s\n", domain, zone.Name)
		} else {
			fmt.Printf("  %s -> No authoritative zone found\n", domain)
		}
	}
}
