package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/busoc/meex"
	"github.com/busoc/meex/cmd/internal/multireader"
	"github.com/busoc/timutil"
	"github.com/midbel/xxh"
)

type shortError struct {
	Want, Got int
}

func (e shortError) Error() string {
	if e.Want == 0 {
		return fmt.Sprintf("short buffer: not enough bytes available to read headers (%d)", e.Got)
	}
	return fmt.Sprintf("short buffer: got %d bytes, want %d bytes", e.Got, e.Want)
}

func isShortError(err error) bool {
	_, ok := err.(shortError)
	return ok
}

func NotEnoughByte(want, got int) error {
	return shortError{want, got}
}

const (
	UMICodeLen   = 6
	UMIHeaderLen = 25
)

func main() {
	flag.Parse()

	mr, err := multireader.New(flag.Args(), true)
	if err != nil {
		return
	}
	defer mr.Close()

	digest := xxh.New64(0)
	rt := io.TeeReader(meex.NewReader(mr), digest)

	buffer := make([]byte, 4096)
	var total, size int64
	for {
		n, err := rt.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintln(os.Stderr, "unexpected error reading rt:", err)
			os.Exit(2)
		}
		z, err := dumpPacket(buffer[:n], digest.Sum64())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		total++
		size += int64(z)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%d packets (%dMB)\n", total, size>>20)
}

const (
	listRow    = "%s | %8s | %0x | %08x | %12s | %3d | %16x | %016x\n"
	TimeFormat = "2006-01-02 15:04:05.000"
)

func dumpPacket(body []byte, digest uint64) (int, error) {
	if len(body) < UMIHeaderLen {
		return 0, NotEnoughByte(0, len(body))
	}
	h, err := decodeHeader(body[:UMIHeaderLen])
	if err != nil {
		return 0, err
	}

	data := body[UMIHeaderLen:]
	if len(data) > 8 {
		data = data[:8]
	}

	acqtime := make([]byte, 0, 64)
	acqtime = h.Timestamp().AppendFormat(acqtime, TimeFormat)
	fmt.Fprintf(os.Stdout, listRow, acqtime, h.State, h.Code, h.Orbit, h.Type, h.Len, data, digest)
	return int(h.Len), nil
}

func decodeHeader(body []byte) (UMIHeader, error) {
	var h UMIHeader

	h.Size = binary.LittleEndian.Uint32(body[0:])
	h.State = UMIPacketState(body[4])
	h.Orbit = binary.BigEndian.Uint32(body[5:])
	copy(h.Code[:], body[9:15])
	h.Type = UMIValueType(body[15])
	h.Unit = binary.BigEndian.Uint16(body[16:])
	h.Coarse = binary.BigEndian.Uint32(body[18:])
	h.Fine = uint8(body[22])
	h.Len = binary.BigEndian.Uint16(body[23:])

	return h, nil
}

type UMIPacketState uint8

const (
	StateNoValue UMIPacketState = iota
	StateSameValue
	StateNewValue
	StateLatestValue
	StateErrorValue
)

func (u UMIPacketState) String() string {
	switch u {
	default:
		return "***"
	case StateNoValue:
		return "none"
	case StateSameValue:
		return "same"
	case StateNewValue:
		return "new"
	case StateLatestValue:
		return "latest"
	case StateErrorValue:
		return "unavailable"
	}
}

type UMIValueType uint8

const (
	Int32 UMIValueType = iota + 1
	Float64
	Binary8
	Reference
	String8
	Long
	Decimal
	Real
	Exponent
	Time
	DateTime
	StringN
	BinaryN
	Bit
)

func (u UMIValueType) String() string {
	switch u {
	default:
		return "***"
	case Int32, Long:
		return "long"
	case Float64, Real, Exponent, Decimal:
		return "double"
	case Binary8, BinaryN:
		return "binary"
	case Reference:
		return "reference"
	case String8, StringN:
		return "string"
	case DateTime, Time:
		return "time"
	case Bit:
		return "bit"
	}
}

type UMIHeader struct {
	Size   uint32
	Code   [UMICodeLen]byte
	Orbit  uint32
	State  UMIPacketState
	Type   UMIValueType
	Len    uint16
	Unit   uint16
	Coarse uint32
	Fine   uint8
}

func (u UMIHeader) Timestamp() time.Time {
	return timutil.Join5(u.Coarse, u.Fine)
}
