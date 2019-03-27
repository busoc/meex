package multireader

import (
	"io"
	"os"
	"path/filepath"
)

const datfile = ".dat"

type reader struct {
	curr  *os.File
	files chan string
}

func New(files []string, recurse bool) (io.ReadCloser, error) {
	r := &reader{files: walk(files, recurse)}
	if curr, err := r.openFile(); err != nil {
		return nil, err
	} else {
		r.curr = curr
	}

	return r, nil
}

func (r *reader) Close() error {
	return r.curr.Close()
}

func (r *reader) Read(bs []byte) (int, error) {
	n, err := r.curr.Read(bs)
	if err != nil {
		if err == io.EOF {
			r.curr.Close()
			r.curr, err = r.openFile()
			if err == nil {
				return r.Read(bs)
			}
		}
	}
	return n, err
}

func (r *reader) openFile() (*os.File, error) {
	f, ok := <-r.files
	if !ok {
		return nil, io.EOF
	}
	return os.Open(f)
}

func walk(files []string, recurse bool) chan string {
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
				if e := filepath.Ext(p); e == datfile {
					q <- p
				}
				return nil
			})
		}
	}()
	return q
}
