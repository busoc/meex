package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/midbel/cli"
)

var takeCommand = &cli.Command{
	Usage: "take [-n] <source> <target>",
	Alias: []string{"split"},
	Short: "splits randomly packets from source file to target file(s) into a new file",
	Run:   runTake,
}

var mixCommand = &cli.Command{
	Usage: "mix [-s] [-t] [-u] <file>",
	Alias: []string{"blend"},
	Short: "take two rt files and mix their packets randomly into a new one",
	Run:   runMix,
}

var shuffleCommand = &cli.Command{
	Usage: "shuffle [-k] <source> <target>",
	Short: "shuffle packets from RT files",
	Run:   runShuffle,
}

func runShuffle(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	source, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.Create(cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	defer target.Close()

	s, err := NewShuffler(source, kind.Decod)
	if err != nil {
		return err
	}

	_, err = io.CopyBuffer(NoDuplicate(target), s, make([]byte, MaxBufferSize))
	return err
}

func runMix(cmd *cli.Command, args []string) error {
	uniq := cmd.Flag.Bool("u", false, "no duplicate")
	src := cmd.Flag.String("s", "", "source file")
	dst := cmd.Flag.String("t", "", "target file")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	source, err := ScanFile(*src)
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := ScanFile(*dst)
	if err != nil {
		return err
	}
	defer target.Close()

	file := cmd.Flag.Arg(0)
	if d, f := filepath.Split(file); f == "" {
		file = filepath.Join(d, "mix.dat")
	}
	w, err := os.Create(file)
	if err != nil {
		return err
	}
	defer w.Close()

	var ws io.Writer = w
	if *uniq {
		ws = NoDuplicate(ws)
	}
	_, err = io.CopyBuffer(ws, MixReader(source, target), make([]byte, MaxBufferSize))
	return err
}

func runTake(cmd *cli.Command, args []string) error {
	parts := cmd.Flag.Int("n", 2, "parts")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	r, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer r.Close()

	file := cmd.Flag.Arg(1)
	if d, f := filepath.Split(file); f == "" {
		file = filepath.Join(d, "meex.dat")
	}

	w, err := SplitWriter(file, *parts)
	if err != nil {
		return err
	}
	defer w.Close()

	ws, s := NoDuplicate(w), Scan(r)
	for s.Scan() {
		if _, err := ws.Write(s.Bytes()); err != nil {
			return err
		}
	}
	return s.Err()
}
