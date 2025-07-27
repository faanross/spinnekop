package logging

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Global logger instance
var (
	globalLogger *slog.Logger
	once         sync.Once // ensures our logger is only ever created once
	initError    error
)

// Initialize sets up our global logger
func Initialize(config srv_models.LoggingConfig) error {
	once.Do(func() {
		globalLogger, initError = setupLogging(config)
		if initError == nil {
			// Also set as slog default so slog.Info() etc. work globally
			slog.SetDefault(globalLogger)
		}
	})
	return initError
}

// setupLogging creates and configures a logger handler based on our configuration
func setupLogging(config srv_models.LoggingConfig) (*slog.Logger, error) {
	// Determine log level
	var level slog.Level
	switch strings.ToUpper(config.Level) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Determine output destination
	var output io.Writer
	switch strings.ToUpper(config.Output) {
	case "STDOUT":
		output = os.Stdout
	case "STDERR":
		output = os.Stderr
	default:
		// Assume it's a file path
		file, err := os.OpenFile(config.Output,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", config.Output, err)
		}
		output = file
	}

	output = &prefixWriter{
		prefix: "[*] ",
		writer: output,
	}

	// Create appropriate handler based on format
	var handler slog.Handler
	handlerOptions := &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
	}

	switch strings.ToUpper(config.Format) {
	case "JSON":
		handler = slog.NewJSONHandler(output, handlerOptions)
	case "TEXT":
		handler = slog.NewTextHandler(output, handlerOptions)
	default:
		handler = slog.NewTextHandler(output, handlerOptions)
	}

	// Create and return the logger
	logger := slog.New(handler)
	return logger, nil
}
