package main

import (
	"context"
	"fmt"
	"github.com/faanross/spinnekop/internal/crafter"
	"github.com/faanross/spinnekop/internal/network"
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
	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start send loop in goroutine
	go func() {
		var lastZValue int // track Z-value state
		for {
			select {
			case <-ctx.Done():
				return
			default:
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
						zValueDispatcher(zValue)
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
func zValueDispatcher(z int) {
	switch z {
	case 0:
		fmt.Println("The Z-value of 0 was received")
	case 1:
		fmt.Println("The Z-value of 1 was received")
	case 2:
		fmt.Println("The Z-value of 2 was received")
	case 3:
		fmt.Println("The Z-value of 3 was received")
	default:
		fmt.Println("The Z-value of 4-8 was received")
	}
}
