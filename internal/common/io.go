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

func Banner(s string) string {
	return generic(s, colors[BannerLevel])
}

func Info(s string) string {
	return generic(s, colors[InfoLevel])
}

func Warn(s string) string {
	return generic(fmt.Sprintf("[WARNING]: %v", s), colors[WarnLevel])
}

func Header(s string) string {
	return generic(fmt.Sprintf("[!] %v [!]", s), colors[HeaderLevel])
}

func Error(s string) string {
	return generic(fmt.Sprintf("[ERROR]: %v", s), colors[ErrorLevel])
}
