package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
)

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

	rx, err := setupRoutes(c.Datadir, c.Kind)
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

func setupRoutes(datadir, kind string) (*mux.Router, error) {
	var (
		d   Decoder
		cut int
	)
	switch strings.ToLower(kind) {
	default:
		return nil, fmt.Errorf("unknown/unsupported packet type: %s", kind)
	case "hrd":
		d, cut = DecodeVMU(), HRDLHeaderLen
	case "tm":
		d, cut = DecodeTM(), PTHHeaderLen
	}
	routes := []*route{
		{Name: "meex.json.list", Path: "/packets/", Method: http.MethodGet, Mime: "application/json", Handle: handleList(datadir, d)},
		{Name: "meex.csv.list", Path: "/packets/", Method: http.MethodGet, Mime: "text/csv", Handle: handleList(datadir, d)},
		{Name: "meex.json.gaps", Path: "/gaps/", Method: http.MethodGet, Mime: "application/json", Handle: handleGaps(datadir, d)},
		{Name: "meex.csv.gaps", Path: "/gaps/", Method: http.MethodGet, Mime: "text/csv", Handle: handleGaps(datadir, d)},
		{Name: "meex.json.stats", Path: "/stats/", Method: http.MethodGet, Mime: "application/json", Handle: handleStatus(datadir, d)},
		{Name: "meex.csv.stats", Path: "/stats/", Method: http.MethodGet, Mime: "text/csv", Handle: handleStatus(datadir, d)},
	}
	rx := mux.NewRouter()
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
		rx.Handle(r.Path, f).Name(r.Name).Headers("Accept", r.Mime).Methods(r.Method)
	}
	rx.Handle("/archives/", handleDownloads(datadir, cut, d)).Name("meex.downloads").Headers("Accept", "application/octet-stream").Methods(http.MethodGet)
	return rx, nil
}

func handleDownloads(datadir string, cut int, d Decoder) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		fd, td, err := timeRange(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
    var ds Decoder = d
    q := r.URL.Query()
    if i, err := strconv.Atoi(q.Get("id")); err != nil && q.Get("id") != "" {
      http.Error(w, err.Error(), http.StatusBadRequest)
    } else {
      ds = DecodeById(i, d)
    }
		queue := Walk(ListPaths(datadir, fd, td), ds)
		ws := NoDuplicate(w)
		for p := range queue {
			bs := p.Bytes()
			if _, err := ws.Write(bs[cut:]); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	return http.HandlerFunc(f)
}

func handleStatus(datadir string, d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		fd, td, err := timeRange(r)
		if err != nil {
			return nil, err
		}
		queue := Walk(ListPaths(datadir, fd, td), d)

		gs := make(map[int]*Coze)
		ps := make(map[int]Packet)
		for p := range queue {
			id, _ := p.Id()
			c, ok := gs[id]
			if !ok {
				c = &Coze{Id: id}
			}
			c.Count++
			c.Size += uint64(p.Len())
			if g := p.Diff(ps[id]); g != nil {
				c.Missing += uint64(g.Missing())
			}
			if p, ok := p.(*VMUPacket); ok && p.HRH.Error != 0 {
				c.Error++
			}
			gs[id], ps[id] = c, p
		}
		var rs []*Coze
		for _, c := range gs {
			rs = append(rs, c)
		}
		return rs, nil
	}
}

func handleGaps(datadir string, d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		fd, td, err := timeRange(r)
		if err != nil {
			return nil, err
		}
		var ds []*Gap
		queue := Walk(ListPaths(datadir, fd, td), d)
		gs := make(map[int]Packet)
		for curr := range queue {
			id, _ := curr.Id()
			g := curr.Diff(gs[id])
			if g != nil {
				ds = append(ds, g)
			}
			gs[id] = curr
		}
		return ds, nil
	}
}

func handleList(datadir string, d Decoder) Handler {
	return func(r *http.Request) (interface{}, error) {
		fd, td, err := timeRange(r)
		if err != nil {
			return nil, err
		}
		queue := Walk(ListPaths(datadir, fd, td), d)
		var ds []*Info
		for p := range queue {
			ds = append(ds, p.PacketInfo())
		}
		return ds, nil
	}
}

func timeRange(r *http.Request) (fd time.Time, td time.Time, err error) {
	q := r.URL.Query()
	if fd, err = time.Parse(time.RFC3339, q.Get("dtstart")); q.Get("dtstart") != "" && err != nil {
		return
	}
	if td, err = time.Parse(time.RFC3339, q.Get("dtend")); q.Get("dtend") != "" && err != nil {
		return
	}

	if fd.IsZero() && td.IsZero() {
		td = time.Now()
		fd = td.Add(time.Hour * time.Duration(-24))
	}
	if fd.IsZero() || td.IsZero() {
		err = fmt.Errorf("both dtstart and dtend should be provided")
		return
	}
	if td.Before(fd) || td.Sub(fd) > MaxInterval {
		err = fmt.Errorf("invalid interval")
		return
	}
	err = nil

	fd = fd.Truncate(Five)
	td = td.Add(Five).Truncate(Five)
	return
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
		w.Header().Set("content-type", "application/json")
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
		w.Header().Set("content-type", "text/csv")
		ws := csv.NewWriter(w)
		defer ws.Flush()
		switch ds := ds.(type) {
		default:
			w.WriteHeader(http.StatusNotImplemented)
		case []*Coze:
			var row []string
			for _, c := range ds {
				row = []string{
					strconv.Itoa(c.Id),
					strconv.FormatUint(c.Size, 10),
					strconv.FormatUint(c.Count, 10),
					strconv.FormatUint(c.Missing, 10),
					strconv.FormatUint(c.Error, 10),
				}
				if err := ws.Write(row); err != nil {
					break
				}
			}
		case []*Gap:
			var row []string
			for _, c := range ds {
				row = []string{
					strconv.Itoa(c.Id),
					c.Starts.Format(time.RFC3339),
					c.Ends.Format(time.RFC3339),
					strconv.FormatFloat(c.Duration().Seconds(), 'f', -1, 64),
					strconv.Itoa(c.Last),
					strconv.Itoa(c.First),
					strconv.Itoa(c.Missing()),
				}
				if err := ws.Write(row); err != nil {
					break
				}
			}
		case []*Info:
			var row []string
			for _, c := range ds {
				row = []string{
					strconv.Itoa(c.Id),
					c.AcqTime.Format(time.RFC3339),
					strconv.Itoa(c.Sequence),
					strconv.Itoa(c.Size),
					strconv.FormatUint(uint64(c.Sum), 10),
				}
				if err := ws.Write(row); err != nil {
					break
				}
			}
		}
	}
	return http.HandlerFunc(f)
}
