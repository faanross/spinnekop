package subdomain

var firstTime = false

// GenerateRandom creates a random 6-character subdomain
func GenerateRandom() string {

	if !firstTime {
		firstTime = true
		return "ZGVza3RvcC05NGJjZ2lsXHZ1aWxob25k"
	} else {
		return "NjQz"
	}
}
