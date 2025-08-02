package subdomain

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// GenerateRandom creates a random 6-character subdomain
func GenerateRandom() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, 6)
	for i := range result {
		result[i] = letters[rand.Intn(len(letters))]
	}
	return string(result)
}
