package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
	"unicode"

	"github.com/busoc/meex"
	"github.com/busoc/meex/cmd/internal/multireader"
	"github.com/busoc/timutil"
)

const (
	UPILen        = 32
	HRDLHeaderLen = 18
	VMUHeaderLen  = 24
)

const (
	modeRT = "realtime"
	modePB = "playback"
)

const (
	chanVic1 = "vic1"
	chanVic2 = "vic2"
	chanLRSD = "lrsd"
)

const listRow = "%9d | %04x || %s | %9d | %s | %5s || %02x | %s | %9d | %16s | %s\n"

const TimeFormat = "2006-01-02 15:04:05.000"

var unknown = []byte("***")

func main() {
	mem := flag.String("m", "", "memory profile")
	flag.Parse()

	if *mem != "" {
		defer func() {
			w, err := os.Create(*mem)
			if err != nil {
				return
			}
			defer w.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(w); err != nil {
				return
			}
		}()
	}

	mr, err := multireader.New(flag.Args(), true)
	if err != nil {
		return
	}
	defer mr.Close()

	rt := meex.NewReader(mr)

	buffer := make([]byte, meex.MaxBufferSize)

	var r bytes.Reader
	for {
		n, err := rt.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintln(os.Stderr, "unexpected error reading rt:", err)
			os.Exit(2)
		}
		r.Reset(buffer[:n])
		if err := dumpPacket(os.Stdout, buffer[:n]); err != nil {
			fmt.Fprintln(os.Stderr, "unexpected error:", err)
			os.Exit(2)
		}
	}
}

func dumpPacket(w io.Writer, body []byte) error {
	if len(body) < HRDLHeaderLen+VMUHeaderLen+UPILen {
		return nil
	}
	var (
		h HRDLHeader
		v VMUHeader
		c VMUCommonHeader
	)
	if err := decodeHRDL(body[:HRDLHeaderLen], &h); err != nil {
		return err
	}
	if err := decodeVMU(body[HRDLHeaderLen:HRDLHeaderLen+VMUHeaderLen], &v); err != nil {
		return err
	}
	if len(body[HRDLHeaderLen+VMUHeaderLen:]) < 76 {
		return nil
	}
	if err := decodeCommon(body[HRDLHeaderLen+VMUHeaderLen:], &c); err != nil {
		return nil
	}
	delta := h.Elapsed()
	vmutime := v.Timestamp().Format(TimeFormat)
	acqtime := c.Acquisition().Format(TimeFormat)
	channel, mode := whichChannel(v.Channel), whichMode(v.Origin, c.Origin)
	_, err := fmt.Fprintf(w, listRow, v.Size, h.Error, vmutime, v.Sequence, mode, channel, c.Origin, acqtime, c.Counter, c.UserInfo(), delta)
	return err
}

type HRDLHeader struct {
	Size         uint32
	Error        uint16
	Channel      uint8
	Payload      uint8
	PacketCoarse uint32
	PacketFine   uint8
	HRDPCoarse   uint32
	HRDPFine     uint8
}

func (h HRDLHeader) Elapsed() time.Duration {
	return h.Archive().Sub(h.Acquisition())
}

func (h HRDLHeader) Acquisition() time.Time {
	return timutil.Join5(h.PacketCoarse, h.PacketFine)
}

func (h HRDLHeader) Archive() time.Time {
	return timutil.Join5(h.HRDPCoarse, h.HRDPFine)
}

type VMUHeader struct {
	Size     uint32
	Channel  uint8
	Origin   uint8
	Sequence uint32
	Coarse   uint32
	Fine     uint16
}

func (v VMUHeader) Timestamp() time.Time {
	return timutil.Join6(v.Coarse, v.Fine)
}

type VMUCommonHeader struct {
	Property uint8
	Origin   uint8
	AcqTime  time.Duration
	AuxTime  time.Duration
	Stream   uint16
	Counter  uint32
	UPI      [UPILen]byte
}

func (v VMUCommonHeader) UserInfo() []byte {
	ns := bytes.Map(keepRune, v.UPI[:])
	if len(ns) == 0 {
		return unknown
	}
	return ns
}

func (v VMUCommonHeader) Acquisition() time.Time {
	return timutil.GPS.Add(v.AcqTime)
}

func (v VMUCommonHeader) Auxiliary() time.Time {
	return timutil.GPS.Add(v.AuxTime)
}

func decodeHRDL(body []byte, h *HRDLHeader) error {
	h.Size = binary.LittleEndian.Uint32(body)
	h.Error = binary.BigEndian.Uint16(body[4:])
	h.Payload = uint8(body[6])
	h.Channel = uint8(body[7])
	h.PacketCoarse = binary.BigEndian.Uint32(body[8:])
	h.PacketFine = uint8(body[12])
	h.HRDPCoarse = binary.BigEndian.Uint32(body[13:])
	h.HRDPFine = uint8(body[17])

	return nil
}

func decodeVMU(body []byte, v *VMUHeader) error {
	v.Size = binary.LittleEndian.Uint32(body[4:])
	v.Channel = uint8(body[8])
	v.Origin = uint8(body[9])
	v.Sequence = binary.LittleEndian.Uint32(body[12:])
	v.Coarse = binary.LittleEndian.Uint32(body[16:])
	v.Fine = binary.LittleEndian.Uint16(body[20:])

	return nil
}

func decodeCommon(body []byte, v *VMUCommonHeader) error {
	v.Property = body[0]
	v.Stream = binary.LittleEndian.Uint16(body[1:])
	v.Counter = binary.LittleEndian.Uint32(body[3:])
	v.AcqTime = time.Duration(binary.LittleEndian.Uint64(body[7:]))
	v.AuxTime = time.Duration(binary.LittleEndian.Uint64(body[15:]))
	v.Origin = body[23]

	switch v.Property >> 4 {
	case 1: // science
		copy(v.UPI[:], body[24:])
	case 2: // image
		copy(v.UPI[:], body[44:])
	}
	return nil
}

func whichChannel(c uint8) string {
	switch c {
	case 1:
		return chanVic1
	case 2:
		return chanVic2
	case 3:
		return chanLRSD
	default:
		return "****"
	}
}

func whichMode(vmu, hrd uint8) string {
	if vmu == hrd {
		return modeRT
	}
	return modePB
}

func keepRune(r rune) rune {
	if r == 0 {
		return -1
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
		return r
	}
	return '*'
}
