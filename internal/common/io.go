package common

import "fmt"

const (
	BannerLevel = "banner"
	ErrorLevel  = "high"
	WarnLevel   = "warning"
	HeaderLevel = "header"
	Reset       = "reset"
	InfoLevel   = "info"
)

var colors = map[string]string{
	"banner":  "\033[0;35m", // purple
	"high":    "\033[0;31m", // red
	"warning": "\033[1;33m", // yellow
	"info":    "\033[0;36m", // cyan
	"header":  "\033[0;32m", // green
	"reset":   "\033[0m",    // reset
}

func generic(s string, color string) string {
	return fmt.Sprintf("%v%v%v", color, s, colors[Reset])
}

// Banner formats the provided string into banner format
func Banner(s string) string {
	return generic(s, colors[BannerLevel])
}

// Info formats the provided string into info format
func Info(s string) string {
	return generic(s, colors[InfoLevel])
}

// Warn formats the provided string into warning format
// it is used when a portion of a check detects a vulnerability
func Warn(s string) string {
	return generic(fmt.Sprintf("[WARNING]: %v", s), colors[WarnLevel])
}

// Header formats the provided string into header format
// it is used to format header of the output for a check
func Header(s string) string {
	return generic(fmt.Sprintf("[!] %v [!]", s), colors[HeaderLevel])
}

// Error formats the provided string into error format
// it is used to format errors to be printed out on stdout
func Error(s string) string {
	return generic(fmt.Sprintf("[ERROR]: %v", s), colors[ErrorLevel])
}
