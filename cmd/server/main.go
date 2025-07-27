package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"os"
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
		os.Exit(1)
	}

	// print loaded config

	// create our global logger
	err = logging.Initialize(config.Logging)
	if err != nil {
		fmt.Printf("Failed to initialize logging: %v\n", err)
	}
	printStartUpInfo(configPath, config)

	// TODO REFORMAT USING LOGGER

	// loader.PrintConfiguration()

	// perform zone consistency checks
	if err := loader.ValidateZoneConsistency(); err != nil {
		fmt.Printf("Zone consistency check failed: %v\n", err)
		return
	}

	fmt.Println("\nConfiguration loaded and validated successfully!")

}
