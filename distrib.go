package main

import (
	"net/http"
	"net/url"
	"os"
	"time"

	_ "github.com/boltdb/bolt"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
)

type InvalidRequestError string

func (i InvalidRequestError) Error() string {
	return string(i)
}

var distribCommand = &cli.Command{
	Usage: "distrib [-d] <config.toml>",
	Short: "run a REST server",
	Run:   runDistrib,
}

func runDistrib(cmd *cli.Command, args []string) error {
	devel := cmd.Flag.Bool("d", false, "development")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	r, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer r.Close()
	c := struct {
		Addr    string `toml:"address"`
		Datadir string `toml:"datadir"`
		Kind    string `toml:"type"`
	}{}
	if err := toml.NewDecoder(r).Decode(&c); err != nil {
		return err
	}
	if *devel {

	}
	return http.ListenAndServe(c.Addr, nil)
}

func timeRange(q url.Values) (time.Time, time.Time, error) {
	var (
		fd, td time.Time
		err    error
	)
	if fd, err = time.Parse(time.RFC3339, q.Get("dtstart")); err != nil && q.Get("dtstart") != "" {
		return fd, td, InvalidRequestError("invalid format for dtstart")
	}
	if td, err = time.Parse(time.RFC3339, q.Get("dtend")); err != nil && q.Get("dtend") != "" {
		return fd, td, InvalidRequestError("invalid format for dtend")
	}
	if fd.IsZero() && td.IsZero() {
		td = time.Now()
		fd = td.Add(-time.Hour * 24)
	}
	if td.Before(fd) {
		return fd, td, InvalidRequestError("invalid date range")
	}
	return fd, td, nil
}
