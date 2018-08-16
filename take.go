package main

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

var takeCommand = &cli.Command{
	Usage: "take [-n] <source> <target>",
	Alias: []string{"split"},
	Short: "splits randomly packets from source file to target file(s) into a new file",
	Run:   runTake,
}

var mixCommand = &cli.Command{
	Usage: "mix [-s] [-t] [-u] <file>",
	Alias: []string{"blend"},
	Short: "take two rt files and mix their packets randomly into a new one",
	Run:   runMix,
}

var shuffleCommand = &cli.Command{
	Usage: "shuffle [-k] <source> <target>",
	Short: "shuffle packets from RT files",
	Run:   runShuffle,
}

func runShuffle(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	source, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.Create(cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	defer target.Close()

	s, err := NewShuffler(source, kind.Decod)
	if err != nil {
		return err
	}

	_, err = io.CopyBuffer(NoDuplicate(target), s, make([]byte, MaxBufferSize))
	return err
}

func runMix(cmd *cli.Command, args []string) error {
	uniq := cmd.Flag.Bool("u", false, "no duplicate")
	src := cmd.Flag.String("s", "", "source file")
	dst := cmd.Flag.String("t", "", "target file")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	source, err := ScanFile(*src)
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := ScanFile(*dst)
	if err != nil {
		return err
	}
	defer target.Close()

	file := cmd.Flag.Arg(0)
	if d, f := filepath.Split(file); f == "" {
		file = filepath.Join(d, "mix.dat")
	}
	w, err := os.Create(file)
	if err != nil {
		return err
	}
	defer w.Close()

	var ws io.Writer = w
	if *uniq {
		ws = NoDuplicate(ws)
	}
	_, err = io.CopyBuffer(ws, MixReader(source, target), make([]byte, MaxBufferSize))
	return err
}

func runTake(cmd *cli.Command, args []string) error {
	parts := cmd.Flag.Int("n", 2, "parts")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	r, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer r.Close()

	file := cmd.Flag.Arg(1)
	if d, f := filepath.Split(file); f == "" {
		file = filepath.Join(d, "meex.dat")
	}

	w, err := SplitWriter(file, *parts)
	if err != nil {
		return err
	}
	defer w.Close()

	ws, s := NoDuplicate(w), Scan(r)
	for s.Scan() {
		if _, err := ws.Write(s.Bytes()); err != nil {
			return err
		}
	}
	return s.Err()
}

type shuffler struct {
	pos   int
	index []*Index

	reader io.ReadSeeker
}

func NewShuffler(rs io.ReadSeeker, d Decoder) (io.Reader, error) {
	is := NewReader(rs, d).Index()
	rand.Shuffle(len(is), func(i, j int) { is[i], is[j] = is[j], is[i] })
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return &shuffler{index: is, reader: rs}, nil
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
