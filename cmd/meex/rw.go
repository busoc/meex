package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type SortFunc func([]*Index) []*Index

type joiner struct {
	rs map[string]io.ReadSeeker

	offset int
	index  []*Index
}

func Join(d Decoder, rs ...io.ReadSeeker) (io.Reader, error) {
	return JoinWith(d, nil, rs...)
}

func JoinWith(d Decoder, f SortFunc, rs ...io.ReadSeeker) (io.Reader, error) {
	ms := make(map[string]io.ReadSeeker)
	index := make([]*Index, 0, 300*len(rs)*4)

	var (
		group errgroup.Group
		mu    sync.Mutex
	)
	for _, r := range rs {
		rt := r
		group.Go(func() error {
			ix, sum, err := indexReader(rt, d)
			if err == nil {
				mu.Lock()
				defer mu.Unlock()
				index = append(index, ix...)
				ms[sum] = rt
			}
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	if f == nil {
		sort.Slice(index, func(i, j int) bool {
			return index[i].Timestamp.Before(index[j].Timestamp)
		})
	} else {
		index = f(index)
	}
	return &joiner{rs: ms, index: index}, nil
}

func indexReader(r io.ReadSeeker, d Decoder) ([]*Index, string, error) {
	ix, sum := NewReader(r, d).IndexSum()
	index := make([]*Index, len(ix))
	for j, i := range ix {
		i.Sum = sum
		index[j] = i
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, sum, err
	}
	return index, sum, nil
}

func (j *joiner) Read(bs []byte) (int, error) {
	if len(bs) < MaxBufferSize {
		return 0, io.ErrShortBuffer
	}
	if j.offset >= len(j.index) {
		return 0, io.EOF
	}
	ix := j.index[j.offset]
	j.offset++

	r := j.rs[ix.Sum]
	if _, err := r.Seek(int64(ix.Offset), io.SeekStart); err != nil {
		return 0, err
	}
	return io.ReadFull(r, bs[:ix.Size])
}

type shuffler struct {
	pos   int
	index []*Index

	reader io.ReadSeeker
}

func Sort(r io.ReadSeeker, d Decoder) (io.Reader, error) {
	return SortWith(r, d, nil)
}

func SortWith(r io.ReadSeeker, d Decoder, f SortFunc) (io.Reader, error) {
	ix := NewReader(r, d).Index()
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if f == nil {
		sort.Slice(ix, func(i, j int) bool {
			return ix[i].Timestamp.Before(ix[j].Timestamp)
		})
	} else {
		ix = f(ix)
	}
	return &shuffler{index: ix, reader: r}, nil
}

func Shuffle(rs io.ReadSeeker, d Decoder) (io.Reader, error) {
	ix := NewReader(rs, d).Index()
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	rand.Shuffle(len(ix), func(i, j int) { ix[i], ix[j] = ix[j], ix[i] })
	return &shuffler{index: ix, reader: rs}, nil
}

func (s *shuffler) Read(bs []byte) (int, error) {
	if s.pos >= len(s.index) {
		return 0, io.EOF
	}
	ix := s.index[s.pos]
	if len(bs) < ix.Size {
		return 0, io.ErrShortBuffer
	}
	if _, err := s.reader.Seek(int64(ix.Offset), io.SeekStart); err != nil {
		return 0, err
	}
	s.pos++

	return io.ReadFull(s.reader, bs[:ix.Size])
}

type splitWriters struct {
	writers []io.WriteCloser
}

func SplitWriter(file string, n int) (io.WriteCloser, error) {
	if n < 2 {
		return nil, fmt.Errorf("")
	}
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	rand.Seed(time.Now().Unix())

	ws := make([]io.WriteCloser, n)
	for i := 0; i < n; i++ {
		w, err := os.Create(fmt.Sprintf("%s.%04d", file, i+1))
		if err != nil {
			for j := 0; j < i; j++ {
				ws[j].Close()
				os.Remove(fmt.Sprintf("%s.%04d", file, j+1))
			}
			return nil, err
		}
		ws[i] = w
	}
	return &splitWriters{writers: ws}, nil
}

func (sw *splitWriters) Write(bs []byte) (int, error) {
	ix := rand.Intn(len(sw.writers))
	return sw.writers[ix].Write(bs)
}

func (sw *splitWriters) Close() error {
	var err error
	for _, s := range sw.writers {
		if e := s.Close(); err == nil && e != nil {
			err = e
		}
	}
	return err
}

type mixReaders struct {
	rs []Scanner
}

func MixReader(rs ...Scanner) io.Reader {
	vs := make([]Scanner, len(rs))
	copy(vs, rs)

	return &mixReaders{vs}
}

func (m *mixReaders) Read(bs []byte) (int, error) {
	ix := rand.Intn(len(m.rs))
	if !m.rs[ix].Scan() {
		if len(m.rs) > 1 {
			m.rs = append(m.rs[:ix], m.rs[ix+1:]...)
			ix = (ix + 1) % len(m.rs)
		} else {
			return 0, io.EOF
		}
	}
	return copy(bs, m.rs[ix].Bytes()), m.rs[ix].Err()
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
