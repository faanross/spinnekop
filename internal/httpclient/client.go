package httpclient

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ContactServer sends a GET request to the server's HTTP endpoint
func ContactServer() bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://127.0.0.1:8080/")
	if err != nil {
		fmt.Printf("Error contacting HTTP server: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return false
	}

	fmt.Printf("HTTP Response: %s\n", string(body))
	return true
}

var fileTransferred bool

// TransferFile sends dummy.zip to the server in chunks
func TransferFile() {
	if fileTransferred {
		return
	}

	// Read file
	data, err := os.ReadFile("dummy.zip")
	if err != nil {
		fmt.Printf("Error reading dummy.zip: %v\n", err)
		return
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(data)

	// Chunk size (1MB chunks)
	chunkSize := 1024 * 1024
	totalChunks := (len(encoded) + chunkSize - 1) / chunkSize

	fmt.Printf("Transferring file: %d bytes in %d chunks\n", len(data), totalChunks)

	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}

		chunk := encoded[start:end]

		resp, err := client.Post(
			fmt.Sprintf("http://127.0.0.1:8080/upload?chunk=%d&total=%d", i, totalChunks),
			"text/plain",
			bytes.NewReader([]byte(chunk)),
		)
		if err != nil {
			fmt.Printf("Error sending chunk %d: %v\n", i, err)
			return
		}
		resp.Body.Close()

		fmt.Printf("Sent chunk %d/%d\n", i+1, totalChunks)
	}

	fileTransferred = true
	fmt.Println("File transfer complete")
}
