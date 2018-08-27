package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
)

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
		Addr      string   `toml:"address"`
		Datadir   string   `toml:"datadir"`
		Kind      string   `toml:"type"`
		Instances []string `toml:"instances"`
	}{}
	if err := toml.NewDecoder(r).Decode(&c); err != nil {
		return err
	}

	rx, err := setupRoutes(c.Datadir, c.Kind, c.Instances)
	if err != nil {
		return err
	}

	var h http.Handler = rx
	if *devel {
		h = handlers.LoggingHandler(os.Stderr, handlers.CompressHandler(h))
		h = handlers.CORS()(h)
	}
	return http.ListenAndServe(c.Addr, h)
}

type route struct {
	Handle Handler
	Name   string
	Path   string
	Mime   string
	Method string
}

func setupRoutes(datadir, kind string, is []string) (*mux.Router, error) {
	if len(is) == 0 {
		return nil, fmt.Errorf("at least one instance should be configured")
	}
	var d Decoder
	switch strings.ToLower(kind) {
	default:
		return nil, fmt.Errorf("unknown/unsupported packet type: %s", kind)
	case "hrd":
		d = DecodeVMU()
	case "tm":
		d = DecodeTM()
	}
	routes := []*route{
		{Name: "meex.json.list", Path: "/packets/", Method: http.MethodGet, Mime: "application/json", Handle: handleList(d)},
		{Name: "meex.json.gaps", Path: "/gaps/", Method: http.MethodGet, Mime: "application/json", Handle: handleGaps(d)},
		{Name: "meex.json.stats", Path: "/stats/", Method: http.MethodGet, Mime: "application/json", Handle: handleStatus(d)},
		{Name: "meex.csv.list", Path: "/packets/", Method: http.MethodGet, Mime: "text/csv", Handle: handleList(d)},
		{Name: "meex.csv.gaps", Path: "/gaps/", Method: http.MethodGet, Mime: "text/csv", Handle: handleGaps(d)},
		{Name: "meex.csv.stats", Path: "/stats/", Method: http.MethodGet, Mime: "text/csv", Handle: handleStatus(d)},
	}
	rx := mux.NewRouter()
	for _, i := range is {
		s := rx.PathPrefix("/" + i).Subrouter()
		for _, r := range routes {
			var f http.Handler
			switch r.Mime {
			default:
				continue
			case "application/json":
				f = negociateJSON(r.Handle)
			case "text/csv":
				f = negociateCSV(r.Handle)
			}
			s.Handle(r.Path, f).Name(r.Name+"."+i).Headers("Accept", r.Mime).Methods(r.Method)
		}
	}
	return rx, nil
}

func handleStatus(d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		return nil, nil
	}
}

func handleGaps(d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		return nil, nil
	}
}

func handleList(d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		return nil, nil
	}
}

func negociateJSON(h Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		ds, err := h(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ds == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		json.NewEncoder(w).Encode(ds)
	}
	return http.HandlerFunc(f)
}

func negociateCSV(h Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		ds, err := h(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ds == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	return http.HandlerFunc(f)
}
