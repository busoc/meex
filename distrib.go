package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
	"golang.org/x/sync/errgroup"
)

type InvalidRequestError string

func (i InvalidRequestError) Error() string {
	return string(i)
}

const MaxInterval = time.Hour * 24

var distribCommand = &cli.Command{
	Usage: "distrib [-d] <config.toml>",
	Short: "run a REST server",
	Run:   runDistrib,
}

type Handler func(*http.Request) (interface{}, error)

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
	return http.ListenAndServe(c.Addr, nil)
}
