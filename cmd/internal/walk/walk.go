package walk

import (
	"io"
	"os"
	"path/filepath"

	"github.com/busoc/meex"
)

func Walk(ps []string, d meex.Decoder) <-chan meex.Packet {
	q := make(chan meex.Packet)
	go func() {
		defer close(q)
		for _, p := range ps {
			if err := walk(p, d, q); err != nil {
				return
			}
		}
	}()
	return q
}

func walk(p string, d meex.Decoder, q chan<- meex.Packet) error {
	rt := meex.NewReader(nil, d)
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

		rt.Reset(r)
		for {
			p, err := rt.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			q <- p
		}
		return nil
	})
}
