package main

import (
	"context"
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/server"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	if err != nil {
		logging.Error("Failed to create DNS server",
			"error", err)
		os.Exit(1)
	}

	// set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		logging.Info("Starting DNS server", "address", config.Server.GetAddress())
		serverErr <- dnsServer.Start(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logging.Info("Received shutdown signal", "signal", sig.String())
	case err := <-serverErr:
		if err != nil {
			logging.Error("Server error", "error", err)
		}
	}

	// Graceful shutdown
	logging.Info("Shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := dnsServer.Shutdown(shutdownCtx); err != nil {
		logging.Error("Shutdown error", "error", err)
		os.Exit(1)
	}

	logging.Info("Server stopped successfully")

}
