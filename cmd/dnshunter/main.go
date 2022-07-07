package main

import (
	"fmt"
	"log"
	"os"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/runner"
)

func main() {
	cfg, err := runner.ParseArgs()
	if err != nil {
		log.Fatal(err)
	}

	if cfg.IsHelpVersion() {
		os.Exit(0)
	}

	fmt.Println(common.BannerFmt(common.Banner))
	if err := cfg.Run(); err != nil {
		log.Fatal(err)
	}
}
