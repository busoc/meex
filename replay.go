package main

import (
	"github.com/midbel/cli"
)

var replayCommand = &cli.Command{
	Usage: "replay [-k] [-d] [-r] <addr>",
	Short: "replay packets from rt files",
	// Run:   runReplay,
}

func runReplay(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}
