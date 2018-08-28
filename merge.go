package main

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

const Five = time.Minute * 5

var sortCommand = &cli.Command{
	Usage: "sort [-k] <source> <target>",
	Short: "sort packets found in a RT file",
	Run:   runSort,
}

var joinCommand = &cli.Command{
	Usage: "merge [-k] [-s] [-t] <file>",
	Alias: []string{"join"},
	Short: "merge packets into RT file(s)",
	Run:   runJoin,
}

func runJoin(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	src := cmd.Flag.String("s", "", "source file")
	dst := cmd.Flag.String("t", "", "dest file")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	source, err := os.Open(*src)
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.Open(*dst)
	if err != nil {
		return err
	}
	defer target.Close()

	tgt := cmd.Flag.Arg(0)
	if err := os.MkdirAll(filepath.Dir(tgt), 0755); err != nil && !os.IsExist(err) {
		return err
	}
	w, err := os.Create(tgt)
	if err != nil {
		return err
	}
	defer w.Close()

	jr, err := JoinWith(kind.Decod, kind.Sort, source, target)
	if err != nil {
		return err
	}
	_, err = io.CopyBuffer(w, jr, make([]byte, MaxBufferSize))
	return err
}

func runSort(cmd *cli.Command, args []string) error {
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

	s, err := SortWith(source, kind.Decod, kind.Sort)
	if err != nil {
		return err
	}

	_, err = io.CopyBuffer(NoDuplicate(target), s, make([]byte, MaxBufferSize))
	return err
}
