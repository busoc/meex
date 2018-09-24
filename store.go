package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

type buffer struct {
	datadir string
	write   func([]byte) ([]byte, error)

	file *os.File
	tick <-chan time.Time
}

func NewBuffer(dir string, i time.Duration, f func([]byte) ([]byte, error)) (io.WriteCloser, error) {
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	w, err := createFile(dir)
	if err != nil {
		return nil, err
	}
	return &buffer{
		datadir: dir,
		write:   f,
		tick:    time.Tick(i),
		file:    w,
	}, nil
}

func createFile(dir string) (*os.File, error) {
	n := fmt.Sprintf("rt_%s.dat", time.Now().Format("20060102_150405"))
	return os.Create(filepath.Join(dir, n))
}

func (b *buffer) Write(bs []byte) (int, error) {
	select {
	case <-b.tick:
		b.file.Close()
		f, err := createFile(b.datadir)
		if err != nil {
			return 0, err
		}
		b.file = f
	}
	vs, err := b.write(bs)
	if err != nil {
		return 0, err
	}
	if n, err := b.file.Write(vs); err != nil {
		return n, err
	}
	return len(bs), nil
}

func (b *buffer) Close() error {
	if b.file != nil {
		b.file.Close()
		b.file = nil
	}
	return nil
}

var storeCommand = &cli.Command{
	Usage: "store [-k] [-d] [-i] [-p] <addr>",
	Short: "listen and store incoming packets in rt.dat files",
	Run:   runStore,
}

func runStore(cmd *cli.Command, args []string) error {
	kind := cmd.Flag.String("k", "", "packet type")
	datadir := cmd.Flag.String("d", os.TempDir(), "data directory")
	proto := cmd.Flag.String("p", "udp", "protocol")
	interval := cmd.Flag.Duration("i", Five, "interval")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var writeFunc func([]byte) ([]byte, error)
	switch *kind {
	case "tm", "pt", "pth":
		writeFunc = storePTH
	case "pp", "pdh", "pd":
		writeFunc = storePDH
	case "vmu":
		writeFunc = storeVMU
	}
	w, err := NewBuffer(*datadir, *interval, writeFunc)
	if err != nil {
		return err
	}
	defer w.Close()

	switch *proto {
	case "udp":
		return copyUDP(cmd.Flag.Arg(0), w)
	case "tcp":
		return copyTCP(cmd.Flag.Arg(0), w)
	default:
		return fmt.Errorf("unsupported protocol %q", *proto)
	}
}

func copyUDP(addr string, w io.Writer) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	var c *net.UDPConn
	if a.IP.IsMulticast() {
		c, err = net.ListenMulticastUDP("udp", nil, a)
	} else {
		c, err = net.ListenUDP("udp", a)
	}
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = io.Copy(w, c)
	return err
}

func copyTCP(addr string, w io.Writer) error {
	c, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for {
		c, err := c.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(w, c)
		}(c)
	}
	return nil
}

func storePTH(bs []byte) ([]byte, error) {
	vs := make([]byte, len(bs)+10)
	binary.LittleEndian.PutUint32(vs, uint32(len(bs))+6)
	vs[4] = 0x09

	f, c := splitTime5(time.Now(), 0)
	binary.BigEndian.PutUint32(vs[5:], f)
	vs[9] = byte(c)

	copy(vs[10:], bs)
	return vs, nil
}

func storePDH(bs []byte) ([]byte, error) {
	vs := make([]byte, len(bs)+4)
	binary.LittleEndian.PutUint32(vs, uint32(len(bs)))

	copy(vs[4:], bs)
	return vs, nil
}

func storeVMU(bs []byte) ([]byte, error) {
	vs := make([]byte, len(bs)+18)
	binary.LittleEndian.PutUint32(vs, uint32(len(bs))+14)

	//copy VMU timestamp from bs
	copy(vs[7:], bs[16:20])

	c, f := splitTime5(time.Now(), 0)
	binary.BigEndian.PutUint32(vs[12:], c)
	vs[16] = byte(f)

	copy(vs[17:], bs)
	return vs, nil
}
