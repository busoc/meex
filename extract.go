package main

import (
	"fmt"
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

var extractCommand = &cli.Command{
	Usage: "extract [-p] [-k] [-t] [-i] [-d] <rt,...>",
	Alias: []string{"filter"},
	Short: "extract packets from RT file(s)",
	Run:   runExtract,
}

func runExtract(cmd *cli.Command, args []string) error {
	id := cmd.Flag.Int("p", 0, "packet id")
	reception := cmd.Flag.String("t", "", "reception time")
	datadir := cmd.Flag.String("d", os.TempDir(), "data directory")
	interval := cmd.Flag.Duration("i", 0, "interval")
	kind := cmd.Flag.String("k", "", "packet type")
	cut := cmd.Flag.Bool("c", false, "only packets body")
	// deflate := cmd.Flag.Bool("z", false, "compress files")
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
