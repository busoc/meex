package main

import (
  "errors"
  "io"
  "fmt"
  "time"
)

var ErrSkip = errors.New("skip")

type Scanner interface {
	Scan() bool
	Bytes() []byte
	Err() error
}

type ScanCloser interface {
	io.Closer
	Scanner
}

type Lesser interface {
	Less(Packet) bool
}

type Packet interface {
	Id() (int, int)
	Sequence() int
	Diff(Packet) *Gap

	PacketInfo() *Info

	Timestamp() time.Time
	Reception() time.Time
	Error() bool

	Len() int
	Bytes() []byte

	Lesser
}

type HRPacket interface {
	Packet

	Acquisition() time.Time
	Auxiliary() time.Time

	fmt.Stringer
}

type Decoder interface {
	Decode([]byte) (Packet, error)
}

type Info struct {
	Id       int       `json:"id"`
	Sequence int       `json:"sequence"`
	Size     int       `json:"length"`
	AcqTime  time.Time `json:"dtstamp"`
	Sum      uint32    `json:"checksum"`
	Context  string    `json:"context"`
	Type     string    `json:"data"`
}

func (i *Info) String() string {
	switch i.Type {
	case "tm":
		return fmt.Sprint(i.Id)
	case "pp":
		return fmt.Sprintf("%x", i.Id)
	case "vmu":
		return VMUChannel(i.Id).String()
	case "hrd":
		return fmt.Sprintf("%s-%x", i.Context, i.Id)
	default:
		return "invalid"
	}
}

type Gap struct {
	Id     int       `json:"id"`
	Starts time.Time `json:"dtstart"`
	Ends   time.Time `json:"dtend"`
	Last   int       `json:"last"`
	First  int       `json:"first"`
}

type Coze struct {
	Id      int    `json:"id"`
	Size    uint64 `json:"bytes"`
	Count   uint64 `json:"count"`
	Missing uint64 `json:"missing"`
	Error   uint64 `json:"error"`
}

func (c *Coze) Corrupted() float64 {
	if c.Count == 0 && c.Missing == 0 {
		return 0
	}
	return 0
}

func (c *Coze) Update(o *Coze) {
	c.Size += o.Size
	c.Count += o.Count
	c.Error += o.Error
	c.Missing += o.Missing
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
