package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const RT = "rt_%02d_%02d.dat"

const Day = time.Hour * 24

func ListPaths(dir string, fd, td time.Time) []string {
	var ds []string
	for fd.Before(td) {
		ds = append(ds, timePath(dir, fd))
		fd = fd.Add(time.Hour)
		// min := fd.Minute()
		// d := filepath.Join(, fmt.Sprintf(RT, min, min+4))
		// if i, err := os.Stat(d); err == nil && i.Mode().IsRegular() {
		// 	ds = append(ds, d)
		// }
		// fd = fd.Add(Five)
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
			if p == "" {
				continue
			}
			if err := walk(p, q, d); err != nil {
				return
			}
		}
	}()
	return q
}

type KeyGap struct {
	*Gap
	Key string
}

func Gaps(paths []string, d Decoder) <-chan *KeyGap {
	q := make(chan *KeyGap)
	go func() {
		defer close(q)

		gs := make(map[string]Packet)
		for p := range Walk(paths, d) {
			id := defaultPacketKey(p)
			if g := p.Diff(gs[id]); g != nil {
				k := &KeyGap{
					Key: id,
					Gap: g,
				}
				q <- k
			}
			gs[id] = p
		}
	}()
	return q
}

type KeyTimeCoze struct {
	*Coze
	Key  string
	When time.Time
}

func CountByDay(paths []string, d Decoder) <-chan *KeyTimeCoze {
	q := make(chan *KeyTimeCoze)
	go func() {
		defer close(q)

		gs := make(map[string]*KeyTimeCoze)
		ps := make(map[string]Packet)
		for p := range Walk(paths, d) {
			id := defaultPacketKey(p)
			c := gs[id]
			if c != nil && p.Timestamp().Sub(c.When) >= Day {
				q <- c
				delete(gs, id)
			}
			if _, ok := gs[id]; !ok {
				i, _ := p.Id()
				c = &KeyTimeCoze{
					Coze: &Coze{Id: i},
					Key:  id,
					When: p.Timestamp().Truncate(Day),
				}
			}
			c.Count++
			c.Size += uint64(p.Len())
			if g := p.Diff(ps[id]); g != nil {
				c.Missing += uint64(g.Missing())
			}
			if p.Error() {
				c.Error++
			}
			ps[id], gs[id] = p, c
		}
		for _, c := range gs {
			q <- c
		}
	}()
	return q
}

func Infos(paths []string, d Decoder) <-chan *Info {
	q := make(chan *Info)
	go func() {
		defer close(q)
		for p := range Walk(paths, d) {
			q <- p.PacketInfo()
		}
	}()
	return q
}

func walk(p string, q chan Packet, d Decoder) error {
	// var rt *Reader
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

		// if rt == nil {
		// 	rt = NewReader(r, d)
		// } else {
		// 	rt.Reset(r)
		// }
		rt := NewReader(r, d)
		for p := range rt.Packets() {
			q <- p
		}
		return nil
	})
}

func defaultPacketKey(p Packet) string {
	switch p := p.(type) {
	case *TMPacket:
		return fmt.Sprint(p.CCSDS.Apid())
	case *PDPacket:
		return fmt.Sprintf("0x%x", p.UMI.Code[:])
	case *VMUPacket:
		return p.VMU.Channel.String()
	case HRPacket:
		i, _ := p.Id()
		return fmt.Sprintf("%x/%s/%s", i, p.Type(), p.String())
	default:
		i, _ := p.Id()
		return fmt.Sprint(i)
	}
}
