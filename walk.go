package main

import (
	"os"
	"path/filepath"
	"sort"
)

func Walk(paths []string, d Decoder) <-chan Packet {
	if d == nil {
		return nil
	}
	q := make(chan Packet)
	go func() {
		defer close(q)
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
