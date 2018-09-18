package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
	"github.com/midbel/cli"
	"github.com/midbel/toml"
	"golang.org/x/sync/errgroup"
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
	sema := make(chan struct{}, 8)
	rest := cmd.Flag.Arg(0)
	files := cmd.Flag.Args()

	var (
		group errgroup.Group
		count uint64
		total uint64
	)
	now := time.Now()
	for i := range Infos(files[1:], kind.Decod) {
		sema <- struct{}{}
		total++

		d := i
		group.Go(func() error {
			defer func() {
				<-sema
			}()
			var buf bytes.Buffer
			if err := json.NewEncoder(&buf).Encode(d); err != nil {
				return err
			}
			r, err := http.Post(rest+d.String(), "application/json", &buf)
			if err != nil {
				return err
			}
			defer r.Body.Close()
			if r.StatusCode != http.StatusNoContent {
				return fmt.Errorf("unexpected status code: %d", r.StatusCode)
			}
			atomic.AddUint64(&count, 1)
			return nil
		})
	}
	err := group.Wait()
	log.Printf("%d/%d packets pushed to %s (%s)", count, total, rest, time.Since(now))
	return err
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
	rx.Handle("/", ListKeys(db)).Methods(http.MethodGet)
	rx.Handle("/packets/{id:[0-9A-Za-z_-]+}", ListPackets(db)).Methods(http.MethodGet)
	rx.Handle("/packets/{id:[0-9A-Za-z_-]+}", UpdatePackets(db)).Methods(http.MethodPost)
	if h, err := Downloads(c.Datadir, c.Kind); err != nil {
		return err
	} else {
		rx.Handle("/archives/", h).Methods(http.MethodGet)
	}
	if *devel {

	}
	return http.ListenAndServe(c.Addr, rx)
}

func Downloads(datadir, kind string) (http.Handler, error) {
	var d Decoder
	switch kind {
	default:
		return nil, fmt.Errorf("unsupported packet type %q", kind)
	case "tm", "pth":
	case "pp", "pdh":
	case "hr", "hrd":
	case "vmu":
	}
	f := func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		_, _, err := timeRange(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if id, err := strconv.Atoi(q.Get("id")); err == nil {
			d = DecodeById(id, d)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	return http.HandlerFunc(f), nil
}

func ListKeys(db *bolt.DB) http.Handler {
	parseTimeKey := func(bs []byte) time.Time {
		t, _ := time.Parse(time.RFC3339, string(bs))
		return t
	}
	type keystat struct {
		Id     string    `json:"id"`
		Starts time.Time `json:"dtstart"`
		Ends   time.Time `json:"dtend"`
		Count  uint64    `json:"total"`
	}
	f := func(r *http.Request) (interface{}, error) {
		var ks []keystat
		err := db.View(func(tx *bolt.Tx) error {
			return tx.ForEach(func(n []byte, b *bolt.Bucket) error {
				s := b.Stats()
				c := b.Cursor()
				dtstart, _ := c.First()
				dtend, _ := c.Last()

				k := keystat{
					Id:     string(n),
					Count:  uint64(s.KeyN),
					Starts: parseTimeKey(dtstart),
					Ends:   parseTimeKey(dtend),
				}
				ks = append(ks, k)
				return nil
			})
		})
		return ks, err
	}
	return negociate(f)
}

func ListPackets(db *bolt.DB) http.Handler {
	f := func(r *http.Request) (interface{}, error) {
		fd, td, err := timeRange(r.URL.Query())
		if err != nil {
			return nil, err
		}
		id := mux.Vars(r)["id"]
		var ps []*Info
		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(id))
			if b == nil {
				return NotFoundError(id)
			}
			c := b.Cursor()
			min := []byte(fd.Format(time.RFC3339))
			max := []byte(td.Format(time.RFC3339))

			for k, v := c.Seek(min); k != nil && bytes.Compare(k, max) <= 0; k, v = c.Next() {
				var i Info
				if err := json.Unmarshal(v, &i); err != nil {
					return err
				}
				ps = append(ps, &i)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return ps, nil
	}
	return negociate(f)
}

func UpdatePackets(db *bolt.DB) http.Handler {
	f := func(r *http.Request) (interface{}, error) {
		defer r.Body.Close()

		var i Info
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&i); err != nil {
			return nil, err
		}
		id := mux.Vars(r)["id"]
		err := db.Batch(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(id))
			if err != nil {
				return err
			}
			ks := i.AcqTime.Format(time.RFC3339)
			bs, _ := json.Marshal(i)
			return b.Put([]byte(ks), bs)
		})
		return nil, err
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
