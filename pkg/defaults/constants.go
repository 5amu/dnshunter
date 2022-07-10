package defaults

const (
	// DefaultNameserver is used when no other nameserver has been specified
	// it is equivalent to dns.google.com
	DefaultNameserver = "8.8.8.8"
	// DNSAmplificationThreshold is an arbitrary number that the programmer
	// considered to be enough for "response considerably larger than request"
	DNSAmplificationThreshold = 5
)
