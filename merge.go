package main

import (
	"crypto/md5"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/midbel/cli"
)

const Five = time.Minute * 5

var mergeCommand = &cli.Command{
	Usage: "merge [-k] [-r] [-s] [-t] <file>",
	Short: "merge packets into RT file(s)",
	Run:   runMerge,
}

var sortCommand = &cli.Command{
	Usage: "sort [-k] [-r] <source> <target>",
	Short: "sort packets found in a RT file",
	Run:   runSort,
}

func runSort(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	span := cmd.Flag.Duration("r", Five, "time range")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	delta := GPS.Sub(UNIX)
	now := time.Now()
	s, err := mergeFiles(cmd.Flag.Arg(0), cmd.Flag.Arg(0), cmd.Flag.Arg(1), kind.Decod, *span)
	if err == nil && s != nil {
		f := s.Starts.Add(delta).Format(TimeFormat)
		t := s.Ends.Add(delta).Format(TimeFormat)
		ratio := float64(s.Size>>20) / time.Since(now).Seconds()
		log.Printf("%d packets in range %s/%s merged (%.2f MB/s) - rogue packet(s): %d", s.Count, f, t, ratio, s.Rogue)
	}
	return err
}

func runMerge(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	span := cmd.Flag.Duration("r", Five, "time range")
	src := cmd.Flag.String("s", "", "source file")
	dst := cmd.Flag.String("t", "", "dest file")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	delta := GPS.Sub(UNIX)
	now := time.Now()
	s, err := mergeFiles(*src, *dst, cmd.Flag.Arg(0), kind.Decod, *span)
	if err == nil && s != nil {
		f := s.Starts.Add(delta).Format(TimeFormat)
		t := s.Ends.Add(delta).Format(TimeFormat)
		ratio := float64(s.Size>>20) / time.Since(now).Seconds()
		log.Printf("%d packets in range %s/%s merged (%.2f MB/s) - rogue packet(s): %d", s.Count, f, t, ratio, s.Rogue)
	}
	return err
}

func mergeFiles(src, dst, tgt string, d Decoder, span time.Duration) (*MergeStats, error) {
	source, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	target, err := os.Open(dst)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	if err := os.MkdirAll(filepath.Dir(tgt), 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	w, err := os.Create(tgt)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	return NewMerger(w).Merge(NewReader(source, d), NewReader(target, d), span)
}

type MergeStats struct {
	Rogue  uint64
	Count  uint64
	Size   uint64
	Starts time.Time
	Ends   time.Time
}

type Merger struct {
	writer io.Writer
}

func NewMerger(w io.Writer) *Merger {
	return &Merger{writer: NoDuplicate(w)}
}

func (m *Merger) Merge(source, target *Reader, span time.Duration) (*MergeStats, error) {
	src, tgt := source.Packets(), target.Packets()

	p0, p1 := m.scanPackets(src, tgt)

	if span == 0 {
		span = Five
	}
	low := p1.Timestamp().Truncate(span)
	high := low.Add(span)

	if p0 == nil && p1 == nil {
		return nil, nil
	}
	ms := &MergeStats{
		Starts: low,
		Ends:   high,
	}
	for {
		if p0 == nil {
			return ms, m.drain(p1, tgt, ms)
		}
		if p1 == nil {
			return ms, m.drain(p0, src, ms)
		}
		t0, t1 := p0.Timestamp(), p1.Timestamp()
		if isRogue(t0, low, high) {
			ms.Rogue++
			p, ok := <-src
			if !ok {
				return ms, m.drain(p1, tgt, ms)
			}
			p0 = p
			continue
		}
		if isRogue(t1, low, high) {
			ms.Rogue++
			p, ok := <-tgt
			if !ok {
				return ms, m.drain(p0, src, ms)
			}
			p1 = p
			continue
		}
		switch {
		case t0.Equal(t1):
			ps := []Packet{p0, p1}

			var ns []Packet
			ns, p0 = m.scanUntil(t0, src)
			ps = append(ps, ns...)
			ns, p1 = m.scanUntil(t1, tgt)
			ps = append(ps, ns...)

			sort.Slice(ps, func(i, j int) bool { return ps[i].Less(ps[j]) })
			for _, p := range ps {
				if n, err := m.writer.Write(p.Bytes()); err != nil {
					return ms, err
				} else {
					ms.Count++
					ms.Size += uint64(n)
				}
			}
			if p0 == nil && p1 == nil {
				return ms, nil
			}
		case t0.Before(t1):
			if n, err := m.writer.Write(p0.Bytes()); err != nil {
				return ms, err
			} else {
				ms.Count++
				ms.Size += uint64(n)
			}
			p, ok := <-src
			if !ok {
				return ms, m.drain(p1, tgt, ms)
			}
			p0 = p
		case t0.After(t1):
			if n, err := m.writer.Write(p1.Bytes()); err != nil {
				return ms, err
			} else {
				ms.Count++
				ms.Size += uint64(n)
			}
			p, ok := <-tgt
			if !ok {
				return ms, m.drain(p0, src, ms)
			}
			p1 = p
		}
	}
}

func isRogue(t, low, high time.Time) bool {
	return t.Before(low) || t.Equal(high) || t.After(high)
}

func (m *Merger) scanUntil(t time.Time, queue <-chan Packet) ([]Packet, Packet) {
	var ps []Packet
	for {
		p, ok := <-queue
		if ok && p.Timestamp().Equal(t) {
			ps = append(ps, p)
		} else {
			return ps, p
		}
	}
}

func (m *Merger) drain(p Packet, queue <-chan Packet, ms *MergeStats) error {
	if p != nil {
		if n, err := m.writer.Write(p.Bytes()); err != nil {
			return err
		} else {
			ms.Count++
			ms.Size += uint64(n)
		}
	}
	for p := range queue {
		if n, err := m.writer.Write(p.Bytes()); err != nil {
			return err
		} else {
			ms.Count++
			ms.Size += uint64(n)
		}
	}
	return nil
}

func (m *Merger) scanPackets(src, tgt <-chan Packet) (Packet, Packet) {
	var p0, p1 Packet
	if p, ok := <-src; ok {
		p0 = p
	}
	if p, ok := <-tgt; ok {
		p1 = p
	}
	return p0, p1
}

type noDuplicateWriter struct {
	sums  map[[md5.Size]byte]struct{}
	inner io.Writer
}

func NoDuplicate(w io.Writer) io.Writer {
	return &noDuplicateWriter{
		sums:  make(map[[md5.Size]byte]struct{}),
		inner: w,
	}
}

func (w *noDuplicateWriter) Write(bs []byte) (int, error) {
	sum := md5.Sum(bs)
	if _, ok := w.sums[sum]; ok {
		return len(bs), nil
	}
	w.sums[sum] = struct{}{}
	return w.inner.Write(bs)
}
