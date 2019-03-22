package meex

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrSkip = errors.New("packet skip")

const MaxBufferSize = 8 << 20

type Packet interface {
	Len() int
	Id() int
	Sequence() int
	Timestamp() time.Time
	Bytes() []byte
}

type dummy []byte

func (d dummy) Id() int              { return 0 }
func (d dummy) Len() int             { return len(d) }
func (d dummy) Sequence() int        { return 0 }
func (d dummy) Timestamp() time.Time { return time.Now() }
func (d dummy) Bytes() []byte        { return []byte(d) }

type Decoder interface {
	Decode([]byte) (Packet, error)
}

type DecoderFunc func([]byte) (Packet, error)

func (d DecoderFunc) Decode(bs []byte) (Packet, error) {
	return d(bs)
}

func Empty() Decoder {
	f := func(bs []byte) (Packet, error) {
		return dummy(bs), nil
	}
	return DecoderFunc(f)
}

type Reader struct {
	scan    *bufio.Reader
	decoder Decoder
}

func NewReader(r io.Reader, d Decoder) *Reader {
	rs := &Reader{decoder: d}
	rs.Reset(r)
	return rs
}

func (r *Reader) Reset(rs io.Reader) {
	if rs != nil {
		if r.scan == nil {
			r.scan = bufio.NewReaderSize(rs, 4<<10)
		} else {
			r.scan.Reset(rs)
		}
	}
}

func (r *Reader) Next() (Packet, error) {
	var size uint32
	if err := binary.Read(r.scan, binary.LittleEndian, &size); err != nil {
		return nil, err
	}

	xs := make([]byte, int(size)+4)
	binary.LittleEndian.PutUint32(xs, size)
	if _, err := io.ReadFull(r.scan, xs[4:]); err != nil {
		return nil, err
	}
	if r.decoder == nil {
		return nil, ErrSkip
	}
	return r.decoder.Decode(xs)
}
