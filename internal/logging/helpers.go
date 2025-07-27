package logging

import (
	"io"
	"log/slog"
)

// CONVENIENCE METHODS

// Info logs a message at INFO level
func Info(msg string, args ...any) {
	getLogger().Info(msg, args...)
}

// Error logs a message at ERROR level
func Error(msg string, args ...any) {
	getLogger().Error(msg, args...)
}

// Warn logs a message at WARN level
func Warn(msg string, args ...any) {
	getLogger().Warn(msg, args...)
}

// Debug logs a message at DEBUG level
func Debug(msg string, args ...any) {
	getLogger().Debug(msg, args...)
}

// HELPER METHODS

// WithComponent returns a logger with a component field added
func WithComponent(component string) *slog.Logger {
	return getLogger().With("component", component)
}

// WithFields returns a logger with additional fields
func WithFields(args ...any) *slog.Logger {
	return getLogger().With(args...)
}

// ForRequest returns a logger with request-specific fields
func ForRequest(clientIP string, requestID uint16) *slog.Logger {
	return getLogger().With(
		"client", clientIP,
		"request_id", requestID,
	)
}

// COMPONENT-SPECIFIC LOGGERS

// DNSLogger provides DNS-specific logging methods
type DNSLogger struct {
	*slog.Logger
}

// ForDNS returns a logger configured for DNS operations
func ForDNS() DNSLogger {
	return DNSLogger{
		Logger: WithComponent("dns_handler"),
	}
}

// QueryReceived logs an incoming DNS query
func (l DNSLogger) QueryReceived(client, domain, qtype string, qclass uint16) {
	l.Info("DNS query received",
		"client", client,
		"domain", domain,
		"type", qtype,
		"class", qclass,
	)
}

// NonStandardClass logs queries with non-IN class
func (l DNSLogger) NonStandardClass(client, domain string, qclass uint16) {
	l.Warn("Non-standard DNS class detected",
		"client", client,
		"domain", domain,
		"class", qclass,
		"alert", "possible_dns_tunneling",
	)
}

// ResponseSent logs a successful response
func (l DNSLogger) ResponseSent(client string, rcode int, answerCount int) {
	l.Debug("DNS response sent",
		"client", client,
		"rcode", rcode,
		"answers", answerCount,
	)
}

// INTERNAL HELPERS

// getLogger returns the global logger or a default if not initialized
func getLogger() *slog.Logger {
	if globalLogger != nil {
		return globalLogger
	}
	// Fallback to default logger if not initialized (prevent panic)
	return slog.Default()
}

// IsInitialized returns true if the logger has been initialized
func IsInitialized() bool {
	return globalLogger != nil
}

type prefixWriter struct {
	prefix string
	writer io.Writer
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	// Prepend the prefix to the entire write
	prefixed := append([]byte(p.prefix), b...)
	return p.writer.Write(prefixed)
}
