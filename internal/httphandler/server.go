package httphandler

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

var (
	httpServer *http.Server
	once       sync.Once
	chunks     map[int]string
	chunkMutex sync.Mutex
)

// StartHTTPServer starts the HTTP server on port 8080 (only once)
func StartHTTPServer() {
	once.Do(func() {
		chunks = make(map[int]string)

		mux := http.NewServeMux()
		mux.HandleFunc("/", handleRoot)
		mux.HandleFunc("/upload", handleUpload)

		httpServer = &http.Server{
			Addr:    "0.0.0.0:8080",
			Handler: mux,
		}

		go func() {
			fmt.Println("Starting HTTP server on 0.0.0.0:8080")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("HTTP server error: %v\n", err)
			}
		}()
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chunkNum := r.URL.Query().Get("chunk")
	totalChunks := r.URL.Query().Get("total")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	chunkIdx := 0
	fmt.Sscanf(chunkNum, "%d", &chunkIdx)
	total := 0
	fmt.Sscanf(totalChunks, "%d", &total)

	chunkMutex.Lock()
	chunks[chunkIdx] = string(body)

	// Check if all chunks received
	if len(chunks) == total {
		// Reassemble file
		var fullData string
		for i := 0; i < total; i++ {
			fullData += chunks[i]
		}

		// Decode from base64
		decoded, err := base64.StdEncoding.DecodeString(fullData)
		if err != nil {
			fmt.Printf("Error decoding base64: %v\n", err)
		} else {
			// Save file
			err = os.WriteFile("exfilled.zip", decoded, 0644)
			if err != nil {
				fmt.Printf("Error saving file: %v\n", err)
			} else {
				fmt.Printf("File saved: dummy.zip (%d bytes)\n", len(decoded))
			}
		}

		// Clear chunks
		chunks = make(map[int]string)
	}
	chunkMutex.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint has been hit")
	w.Write([]byte("You have hit the endpoint"))
}
