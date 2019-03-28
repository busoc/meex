package meex

import (
	"bufio"
	"encoding/binary"
	"io"
)

const MaxBufferSize = 8 << 20

type Reader struct {
	inner  *bufio.Reader
	needed uint32
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
	r.needed = 0
}

func (r *Reader) Read(xs []byte) (int, error) {
	tmp, err := r.inner.Peek(4)
	if err != nil {
		return 0, err
	}
	r.needed = binary.LittleEndian.Uint32(tmp)
	// if err := binary.Read(r.inner, binary.LittleEndian, &r.needed); err != nil {
	// 	return 0, err
	// }
	offset := int(r.needed) + 4

	if len(xs) < offset {
		return 0, io.ErrShortBuffer
	}
	// binary.LittleEndian.PutUint32(xs, r.needed)
	n, err := io.ReadFull(r.inner, xs[:offset])
	// if err == nil {
	// 	n += 4
	// }
	return n, err
}
