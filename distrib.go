package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
)

type NotFoundError string

func (n NotFoundError) Error() string {
	return string(n)
}

type InvalidRequestError string

func (i InvalidRequestError) Error() string {
	return string(i)
}

type handler func(*http.Request) (interface{}, error)

var distribCommand = &cli.Command{
	Usage: "distrib [-d] <config.toml>",
	Short: "run a REST server",
	Run:   runDistrib,
}

var pushCommand = &cli.Command{
	Usage: "push [-k] <url> <rt,...>",
	Short: "push packet infos to distrib API",
	Run:   runPush,
}

func runPush(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	return nil
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
		Path    string `toml:"database"`
		Datadir string `toml:"datadir"`
		Kind    string `toml:"type"`
	}{}
	if err := toml.NewDecoder(r).Decode(&c); err != nil {
		return err
	}
	db, err := bolt.Open(c.Path, 0644, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	rx := mux.NewRouter()
	rx.Handle("/", StatusList(db)).Methods(http.MethodGet)
	rx.Handle("/", StatusUpdate(db)).Methods(http.MethodPost)
	rx.Handle("/{id:[A-Z0-9-]+}", StatusDetail(db)).Methods(http.MethodGet)
	if *devel {

	}
	return http.ListenAndServe(c.Addr, rx)
}

func StatusDetail(db *bolt.DB) http.Handler {
	f := func(r *http.Request) (interface{}, error) {
		return nil, nil
	}
	return negociate(f)
}

func StatusList(db *bolt.DB) http.Handler {
	f := func(r *http.Request) (interface{}, error) {
		return nil, nil
	}
	return negociate(f)
}

func StatusUpdate(db *bolt.DB) http.Handler {
	f := func(r *http.Request) (interface{}, error) {
		defer r.Body.Close()
		c := struct{}{}
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			return nil, err
		}
		db.Update(func(tx *bolt.Tx) error {
			return nil
		})
		return nil, nil
	}
	return negociate(f)
}

func negociate(h handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		ds, err := h(r)
		if err != nil {
			code := http.StatusInternalServerError
			switch err.(type) {
			case NotFoundError:
				code = http.StatusNotFound
			case InvalidRequestError:
				code = http.StatusBadRequest
			}
			http.Error(w, err.Error(), code)
			return
		}
		if ds == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(ds)
	}
	return http.HandlerFunc(f)
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
