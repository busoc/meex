package meex

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const TimeFormat = "2006-01-02 15:04:05.000"

type TruncatedError int

func (e TruncatedError) Error() string {
	return fmt.Sprintf("rt: truncated %d bytes", int(e))
}

type Coze struct {
	Id      int    `json:"id"`
	Size    uint64 `json:"bytes"`
	Count   uint64 `json:"count"`
	Missing uint64 `json:"missing"`
	Error   uint64 `json:"error"`
}

func (c *Coze) Update(o *Coze) {
	c.Size += o.Size
	c.Count += o.Count
	c.Error += o.Error
	c.Missing += o.Missing
}

type Gap struct {
	Id     int       `json:"id"`
	Starts time.Time `json:"dtstart"`
	Ends   time.Time `json:"dtend"`
	Last   int       `json:"last"`
	First  int       `json:"first"`
}

func (g *Gap) Duration() time.Duration {
	return g.Ends.Sub(g.Starts)
}

func (g *Gap) Missing() int {
	d := g.First - g.Last
	if d < 0 {
		d = -d
	}
	return d - 1
}

type Reader struct {
	inner  *bufio.Reader
	needed int
}

func NewReader(r io.Reader) *Reader {
	var rs Reader
	rs.Reset(r)
	return &rs
}

func (r *Reader) Reset(rs io.Reader) {
	if rs == nil {
		return
	}
	if r.inner == nil {
		r.inner = bufio.NewReader(rs)
	} else {
		r.inner.Reset(rs)
	}
	r.needed = 0
}

func (r *Reader) Read(xs []byte) (int, error) {
	if r.inner == nil {
		return 0, nil
	}
	tmp, err := r.inner.Peek(4)
	if err != nil {
		return 0, err
	}
	r.needed = int(binary.LittleEndian.Uint32(tmp)) + 4
	if len(xs) < r.needed {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(r.inner, xs[:r.needed])
}

type writer struct {
	io.Writer
}

func NewWriter(w io.Writer) io.Writer {
	return &writer{w}
}

func (w *writer) Write(xs []byte) (int, error) {
	n := len(xs)
	if err := binary.Write(w.Writer, binary.LittleEndian, uint32(n)); err != nil {
		return 0, err
	}
	return w.Writer.Write(xs)
}

type multiReader struct {
	inner *os.File
	files <-chan string
}

func Browse(files []string, recurse bool) (io.ReadCloser, error) {
	r := multiReader{files: walk(files, recurse)}
	if f, err := r.openFile(); err != nil {
		return nil, err
	} else {
		r.inner = f
	}
	return &r, nil
}

func (m *multiReader) Read(xs []byte) (int, error) {
	n, err := m.inner.Read(xs)
	if err != nil {
		if err == io.EOF {
			m.inner.Close()
			m.inner, err = m.openFile()
			if err == nil {
				return m.Read(xs)
			}
		}
	}
	return n, err
}

func (m *multiReader) Close() error {
	return m.inner.Close()
}

func (m *multiReader) openFile() (*os.File, error) {
	f, ok := <-m.files
	if !ok {
		return nil, io.EOF
	}
	return os.Open(f)
}

func walk(files []string, recurse bool) <-chan string {
	q := make(chan string)
	go func() {
		defer close(q)
		for i := 0; i < len(files); i++ {
			filepath.Walk(files[i], func(p string, i os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if i.IsDir() {
					if !recurse {
						return filepath.SkipDir
					} else {
						return nil
					}
				}
				if e := filepath.Ext(p); e == ".dat" {
					q <- p
				}
				return nil
			})
		}
	}()
	return q
}
