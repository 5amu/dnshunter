package common

import "fmt"

const (
	BannerLevel = "banner"
	HighLevel   = "high"
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

func Banner(s string) {
	fmt.Printf("%v%v%v\n", colors[BannerLevel], s, colors[Reset])
}

func Info(s string) {
	fmt.Printf("%v%v%v\n", colors[InfoLevel], s, colors[Reset])
}

func Warn(s string) {
	fmt.Printf("%v[WARNING]: %v%v\n", colors[WarnLevel], s, colors[Reset])
}
