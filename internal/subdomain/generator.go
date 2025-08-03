package subdomain

var counter = 0

// note this is just a superficial quick fix to simulate certain behaviour, replace later
func GenerateRandom() string {
	switch counter {
	case 0:
		counter++
		return "ZGVza3RvcC05NGJjZ2lsXHZ1aWxob25k"
	case 1:
		counter++
		return "NjQz"
	default:
		return "www"

	}
}
