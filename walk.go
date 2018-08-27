package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const RT = "rt_%02d_%02d.dat"

func ListPaths(dir string, fd, td time.Time) []string {
	var ds []string
	for fd.Before(td) {
		min := fd.Minute()
		d := filepath.Join(timePath(dir, fd), fmt.Sprintf(RT, min, min+4))
		if i, err := os.Stat(d); err == nil && i.Mode().IsRegular() {
			ds = append(ds, d)
		}
		fd = fd.Add(Five)
	}
	return ds
}

func TimePath(dir string, t time.Time) (string, error) {
	dir = timePath(dir, t)
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return "", err
	}
	min := t.Minute()
	return filepath.Join(dir, fmt.Sprintf(RT, min, min+4)), nil
}

func timePath(dir string, t time.Time) string {
	year := fmt.Sprintf("%04d", t.Year())
	doy := fmt.Sprintf("%03d", t.YearDay())
	hour := fmt.Sprintf("%02d", t.Hour())

	return filepath.Join(dir, year, doy, hour)
}

func Walk(paths []string, d Decoder) <-chan Packet {
	q := make(chan Packet)
	go func() {
		defer close(q)
		if d == nil {
			return
		}
		sort.Strings(paths)
		for _, p := range paths {
			if err := walk(p, q, d); err != nil {
				return
			}
		}
	}()
	return q
}

func walk(p string, q chan Packet, d Decoder) error {
	return filepath.Walk(p, func(p string, i os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if i.IsDir() {
			return nil
		}
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		defer r.Close()

		rt := NewReader(r, d)
		for p := range rt.Packets() {
			q <- p
		}
		return nil
	})
}
