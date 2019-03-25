package meex

import (
	"bufio"
	"encoding/binary"
	"io"
)

const MaxBufferSize = 8 << 20

type Reader struct {
	inner *bufio.Reader
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
		r.inner = bufio.NewReaderSize(rs, 4<<10)
	} else {
		r.inner.Reset(rs)
	}
}

func (r *Reader) Read(xs []byte) (int, error) {
	var size uint32
	if err := binary.Read(r.inner, binary.LittleEndian, &size); err != nil {
		return 0, err
	}
	offset := int(size) + 4

	if len(xs) < offset {
		return 0, io.ErrShortBuffer
	}
	binary.LittleEndian.PutUint32(xs, size)
	return io.ReadFull(r.inner, xs[4:offset])
}
