package zhandler

import (
	"sync"
	"time"
)

var (
	oneHourSleepDone bool
	mu               sync.Mutex
)

// HandleZOne checks if a one-hour sleep should occur
func HandleZOne() (shouldSleepOneHour bool, sleepDuration time.Duration) {
	mu.Lock()
	defer mu.Unlock()

	if !oneHourSleepDone {
		oneHourSleepDone = true
		return true, 1 * time.Hour
	}

	return false, 0
}

// ResetOneHourSleep resets the one-hour sleep flag (for testing)
func ResetOneHourSleep() {
	mu.Lock()
	defer mu.Unlock()
	oneHourSleepDone = false
}
