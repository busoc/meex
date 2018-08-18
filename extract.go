package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
	"golang.org/x/sync/errgroup"
)

type byId struct {
	id    int
	inner Decoder
}

func DecodeById(id int, d Decoder) Decoder {
	return &byId{id, d}
}

func (i *byId) Decode(bs []byte) (Packet, error) {
	if i.inner.Decode == nil {
		return nil, ErrSkip
	}
	p, err := i.inner.Decode(bs)
	if err != nil {
		return p, err
	}
	if i.id > 0 {
		id, _ := p.Id()
		if id != i.id {
			return nil, ErrSkip
		}
	}
	return p, nil
}

var dispatchCommand = &cli.Command{
	Usage: "dispatch [-k] [-d] <rt,...>",
	Short: "dispatch packets in the correct location",
	Run:   runDispatch,
}

var extractCommand = &cli.Command{
	Usage: "extract [-p] [-k] [-t] [-i] [-d] <rt,...>",
	Alias: []string{"filter"},
	Short: "extract packets from RT file(s)",
	Run:   runExtract,
}

func runDispatch(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	datadir := cmd.Flag.String("d", os.TempDir(), "data directory")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*datadir, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	ws := make(map[time.Time]io.WriteCloser)
	delta := GPS.Sub(UNIX)
	for p := range Walk(cmd.Flag.Args(), kind.Decod) {
		t := p.Timestamp().Add(delta).Truncate(Five)
		w, ok := ws[t]
		if !ok {
			file, err := TimePath(*datadir, t)
			if err != nil {
				return err
			}
			w, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer w.Close()
			ws[t] = w
		}
		if _, err := w.Write(p.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func runExtract(cmd *cli.Command, args []string) error {
	id := cmd.Flag.Int("p", 0, "packet id")
	reception := cmd.Flag.String("t", "", "reception time")
	datadir := cmd.Flag.String("d", os.TempDir(), "data directory")
	interval := cmd.Flag.Duration("i", 0, "interval")
	kind := cmd.Flag.String("k", "", "packet type")
	cut := cmd.Flag.Bool("c", false, "only packets body")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var (
		d    Decoder
		size int
	)
	switch *kind {
	default:
		return fmt.Errorf("unsupported packet type %s", *kind)
	case "tm", "TM":
		if *cut {
			size = PTHHeaderLen
		}
		d = DecodeTM()
	case "hrdl", "hrd", "vmu":
		if *cut {
			size = HRDLHeaderLen
		}
		d = DecodeVMU()
	}
	d = DecodeById(*id, d)

	var when time.Time
	if w, err := time.Parse(time.RFC3339, *reception); *reception != "" && err == nil {
		when = w.UTC()
	}
	if err := os.MkdirAll(*datadir, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	var group errgroup.Group

	sema := make(chan struct{}, 4)
	defer close(sema)
	for _, a := range cmd.Flag.Args() {
		src, dst := a, filepath.Join(*datadir, a)
		group.Go(func() error {
			sema <- struct{}{}
			c, err := extractPackets(src, dst, d, size, when, *interval)
			if err != nil {
				os.Remove(dst)
			} else {
				log.Printf("%d/%d packets extracted (%dMB) from %s", c.Missing, c.Count, c.Size>>20, src)
			}
			<-sema
			return err
		})
	}
	return group.Wait()
}

func extractPackets(src, dst string, d Decoder, cut int, when time.Time, interval time.Duration) (*Coze, error) {
	r, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	w, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	rt, ws := NewReader(r, d), NoDuplicate(w)

	var c Coze
	for p := range rt.Packets() {
		c.Count++
		if !shouldKeepPacket(p, when, interval) {
			continue
		}
		bs := p.Bytes()
		if n, err := ws.Write(bs[cut:]); err != nil {
			return nil, err
		} else {
			c.Missing++
			c.Size += uint64(n)
		}
	}
	return &c, nil
}

func shouldKeepPacket(p Packet, ref time.Time, interval time.Duration) bool {
	if ref.IsZero() && interval == 0 {
		return true
	}
	if p.Reception().After(time.Now()) {
		return false
	}
	if !ref.IsZero() && p.Reception().Before(ref) {
		return false
	}
	return interval > 0 && p.Reception().Sub(p.Timestamp()) > interval
}
