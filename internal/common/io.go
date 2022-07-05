package common

import "fmt"

const (
	CriticalLevel = "critical"
	HighLevel     = "high"
	WarnLevel     = "warning"
	HeaderLevel   = "header"
	Reset         = "reset"
)

var colors = map[string]string{
	"critical": "\033[0;35m", // purple
	"high":     "\033[0;31m", // red
	"warning":  "\033[1;33m", // yellow
	"low":      "\033[0;36m", // cyan
	"header":   "\033[0;32m", // green
	"reset":    "\033[0m",    // reset
}

func Warn(s string) string {
	return fmt.Sprintf("%v[WARNING]: %v%v", colors[WarnLevel], s, colors[Reset])
}
