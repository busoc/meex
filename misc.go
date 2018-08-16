package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
	"golang.org/x/sync/errgroup"
)

var sumCommand = &cli.Command{
	Usage: "cksum [-d] <rt,...>",
	Alias: []string{"sum"},
	Short: "compute the checksum of RT file(s)",
	Run:   runSum,
}

var scanCommand = &cli.Command {
	Usage: "scan <rt,...>",
	Short: "fast scanning of RT file(s)",
	Run:   runScan,
}

var indexCommand = &cli.Command {
	Usage: "index [-k] <rt,...>",
	Short: "create an index of packets found in RT files",
	Run: runIndex,
}

func runIndex(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	delta := GPS.Sub(UNIX)
	var (
		ix uint64
		prev time.Time
	)
	for p := range Walk(cmd.Flag.Args(), kind.Decod) {
		t := p.Timestamp().Add(delta)
		if prev.IsZero() || (t.Minute()%5 == 0 && t.Sub(prev) >= Five) {
			prev = t
			ix = 0
		}
		size := p.Len()
		log.Printf("%10d | %s | %9d | %x", ix, t.Format(TimeFormat), size, md5.Sum(p.Bytes()))
		ix += uint64(size)
	}
	return nil
}

func runSum(cmd *cli.Command, args []string) error {
	digest := cmd.Flag.String("d", "", "digest")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var group errgroup.Group
	for _, a := range cmd.Flag.Args() {
		file := a
		group.Go(func() error {
			r, err := os.Open(file)
			if err != nil {
				return err
			}
			defer r.Close()

			var d hash.Hash
			switch *digest {
			default:
				log.Printf("%04x %s", sumRFC1071(r), file)
				return nil
			case "fletcher":
				log.Printf("%08x %s", sumFletcher32(r), file)
				return nil
			case "md5":
				d = md5.New()
			case "sha":
				d = sha1.New()
			}
			if _, err := io.Copy(d, r); err != nil {
				return err
			}
			log.Printf("%x %s", d.Sum(nil), file)
			return nil
		})
	}
	return group.Wait()
}

func runScan(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	now := time.Now()

	var size, count uint64
	for _, a := range cmd.Flag.Args() {
		filepath.Walk(a, func(p string, i os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if i.IsDir() {
				return nil
			}
			sc, err := ScanFile(p)
			if err != nil {
				return err
			}
			for sc.Scan() {
				count++
				size += uint64(len(sc.Bytes()))
			}
			return sc.Err()
		})
	}
	elapsed := time.Since(now)
	ratio := float64(size>>20) / elapsed.Seconds()
	log.Printf("%d packets scanned (%dMB) time: %s (%.2f MB/s)", count, size>>20, elapsed, ratio)
	return nil
}

func sumFletcher32(r io.Reader) uint32 {
	const mod = (1 << 16) - 1
	rs := bufio.NewReader(r)

	var sum1, sum2 uint16
	for {
		var v uint16
		if err := binary.Read(rs, binary.BigEndian, &v); err != nil {
			break
		}
		sum1 = (sum1 + v) % mod
		sum2 = (sum2 + sum1) % mod
	}
	return uint32(sum2)<<16 | uint32(sum1)
}

func sumRFC1071(r io.Reader) uint16 {
	rs := bufio.NewReader(r)

	var s uint32
	for {
		var v uint16
		if err := binary.Read(rs, binary.BigEndian, &v); err != nil {
			break
		}
		s += uint32(v)
	}
	for i := s >> 16; i > 0; i = s >> 16 {
		s = (s & 0xffff) | (s >> 16)
	}
	return uint16(s)
}
