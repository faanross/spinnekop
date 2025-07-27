package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/server"
	"os"
)

// for now just hardcode perhaps implement flags later tbd
var configPath = "./configs/server.yaml"
var currentVersion = "0.1"

func main() {

	// instantiate ConfigLoader struct
	loader := NewConfigLoader(configPath)

	// read + validate + unmarshall config file
	config, err := loader.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		fmt.Printf("Please create config file and save it as: %s\n", configPath)
		os.Exit(1)
	}

	// create our global logger
	err = logging.Initialize(config.Logging)
	if err != nil {
		fmt.Printf("Failed to initialize logging: %v\n", err)
	}

	printStartUpInfo(configPath, config)
	performZoneConsistencyChecks(loader)

	// create our dns server

	dnsServer, err := server.NewDNSServer(config)

}
