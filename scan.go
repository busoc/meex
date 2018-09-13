package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
	"time"
)

const Leap = 18 * time.Second

const MaxBufferSize = 8 << 20

const (
	HRDLHeaderLen  = 18
	VMUHeaderLen   = 24
	PTHHeaderLen   = 10
	CCSDSHeaderLen = 6
	ESAHeaderLen   = 10
	UMIHeaderLen   = 25
)

var ErrSkip = errors.New("skip")

var (
	UNIX = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	GPS  = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
)

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

type Decoder interface {
	Decode([]byte) (Packet, error)
}

type DecoderFunc func([]byte) (Packet, error)

func (d DecoderFunc) Decode(bs []byte) (Packet, error) {
	return d(bs)
}

type Info struct {
	Id       int       `json:"id"`
	Sequence int       `json:"sequence"`
	Size     int       `json:"length"`
	AcqTime  time.Time `json:"dtstamp"`
	Sum      uint32    `json:"checksum"`
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

func (c *Coze) Fill() float64 {
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
	return d
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

const UMICodeLen = 6

type UMIHeader struct {
	Size        uint32
	Code        [UMICodeLen]byte
	Orbit       uint32
	State       UMIPacketState
	Type        UMIValueType
	Len         uint16
	Unit        uint16
	Acquisition time.Time
}

func (u *UMIHeader) UnmarshalBinary(bs []byte) error {
	if u == nil {
		u = new(UMIHeader)
	}
	var (
		coarse uint32
		fine   uint8
	)
	r := bytes.NewReader(bs)
	binary.Read(r, binary.LittleEndian, &u.Size)
	binary.Read(r, binary.BigEndian, &u.State)
	binary.Read(r, binary.BigEndian, &u.Orbit)
	io.ReadFull(r, u.Code[:])
	binary.Read(r, binary.BigEndian, &u.Type)
	binary.Read(r, binary.BigEndian, &u.Unit)
	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)
	binary.Read(r, binary.BigEndian, &u.Len)

	u.Acquisition = readTime5(coarse, fine)
	return nil
}

type PDPacket struct {
	UMI     *UMIHeader
	Payload []byte
}

func DecodePD() Decoder {
	f := func(bs []byte) (Packet, error) {
		if len(bs) < UMIHeaderLen {
			return nil, io.ErrShortBuffer
		}
		var u UMIHeader
		if err := u.UnmarshalBinary(bs); err != nil {
			return nil, err
		}
		p := PDPacket{
			UMI:     &u,
			Payload: bs,
		}
		return &p, nil
	}
	return DecoderFunc(f)
}

func (p *PDPacket) Error() bool {
	return p.UMI.Orbit != 0
}

func (p *PDPacket) PacketInfo() *Info {
	_, code := p.Id()
	return &Info{
		Id:      code,
		Size:    len(p.Payload) - UMIHeaderLen,
		AcqTime: p.Timestamp(),
		Sum:     adler32.Checksum(p.Payload[UMIHeaderLen:]),
	}
}

func (p *PDPacket) Timestamp() time.Time {
	return p.UMI.Acquisition
}

func (p *PDPacket) Reception() time.Time {
	return p.UMI.Acquisition
}

func (p *PDPacket) Id() (int, int) {
	c := binary.BigEndian.Uint64(p.UMI.Code[:])
	return int(p.UMI.Code[0]), int(c)
}

func (p *PDPacket) Sequence() int {
	return 0
}

func (p *PDPacket) Len() int {
	return len(p.Payload)
}

func (p *PDPacket) Less(o Packet) bool {
	return false
}

func (p *PDPacket) Diff(o Packet) *Gap {
	return nil
}

func (p *PDPacket) Bytes() []byte {
	return p.Payload
}

type PTHHeader struct {
	Size      uint32
	Type      uint8
	Reception time.Time
}

func (p *PTHHeader) UnmarshalBinary(bs []byte) error {
	if p == nil {
		p = new(PTHHeader)
	}
	r := bytes.NewReader(bs)
	var (
		coarse uint32
		fine   uint8
	)
	binary.Read(r, binary.LittleEndian, &p.Size)
	binary.Read(r, binary.LittleEndian, &p.Type)
	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)

	p.Reception = readTime5(coarse, fine)

	return nil
}

type CCSDSHeader struct {
	Version  uint16
	Fragment uint16
	Length   uint16
}

func (c *CCSDSHeader) UnmarshalBinary(bs []byte) error {
	if c == nil {
		c = new(CCSDSHeader)
	}
	r := bytes.NewReader(bs)

	binary.Read(r, binary.BigEndian, &c.Version)
	binary.Read(r, binary.BigEndian, &c.Fragment)
	binary.Read(r, binary.BigEndian, &c.Length)

	return nil
}

func (c *CCSDSHeader) Apid() int {
	return int(c.Version & 0x07FF)
}

func (c *CCSDSHeader) Sequence() int {
	return int(c.Fragment & 0x3FFF)
}

type ESAHeader struct {
	Acquisition time.Time
	Source      uint32
	Info        uint8
}

func (e *ESAHeader) UnmarshalBinary(bs []byte) error {
	if e == nil {
		e = new(ESAHeader)
	}
	r := bytes.NewReader(bs)

	var (
		coarse uint32
		fine   uint8
	)
	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)
	binary.Read(r, binary.BigEndian, &e.Info)
	binary.Read(r, binary.BigEndian, &e.Source)

	e.Acquisition = readTime5(coarse, fine)

	return nil
}

type TMPacket struct {
	PTH     *PTHHeader
	CCSDS   *CCSDSHeader
	ESA     *ESAHeader
	Payload []byte
}

func DecodeTM() Decoder {
	f := func(bs []byte) (Packet, error) {
		if len(bs) < PTHHeaderLen+CCSDSHeaderLen+ESAHeaderLen {
			return nil, io.ErrShortBuffer
		}
		var (
			p PTHHeader
			c CCSDSHeader
			e ESAHeader
		)
		if err := p.UnmarshalBinary(bs); err != nil {
			return nil, err
		}
		if err := c.UnmarshalBinary(bs[PTHHeaderLen:]); err != nil {
			return nil, err
		}
		if err := e.UnmarshalBinary(bs[PTHHeaderLen+CCSDSHeaderLen:]); err != nil {
			return nil, err
		}
		t := TMPacket{
			PTH:     &p,
			CCSDS:   &c,
			ESA:     &e,
			Payload: bs,
		}
		return &t, nil
	}
	return DecoderFunc(f)
}

func (t *TMPacket) Error() bool {
	return false
}

func (t *TMPacket) PacketInfo() *Info {
	return &Info{
		Id:       t.CCSDS.Apid(),
		Sequence: t.Sequence(),
		Size:     len(t.Payload) - PTHHeaderLen,
		AcqTime:  t.Timestamp(),
		Sum:      adler32.Checksum(t.Payload[PTHHeaderLen:]),
	}
}

func (t *TMPacket) Timestamp() time.Time {
	return t.ESA.Acquisition
}

func (t *TMPacket) Reception() time.Time {
	return t.PTH.Reception
}

func (t *TMPacket) Id() (int, int) {
	return t.CCSDS.Apid(), int(t.ESA.Source)
}

func (t *TMPacket) Sequence() int {
	return t.CCSDS.Sequence()
}

func (t *TMPacket) Len() int {
	return len(t.Payload)
}

func (t *TMPacket) Less(p Packet) bool {
	return t.Sequence() < p.Sequence()
}

func (t *TMPacket) Diff(o Packet) *Gap {
	if _, ok := o.(*TMPacket); o == nil || !ok {
		return nil
	}
	if o.Timestamp().After(t.Timestamp()) {
		return o.Diff(t)
	}
	s := o.Sequence() + 1
	if s > (1<<14)-1 {
		s = 0
	}
	if t.Sequence() == s {
		return nil
	}
	return &Gap{
		Id:     t.CCSDS.Apid(),
		Starts: o.Timestamp(),
		Ends:   t.Timestamp(),
		First:  t.Sequence(),
		Last:   o.Sequence(),
	}
}

func (t *TMPacket) Bytes() []byte {
	return t.Payload
}

type HRDLHeader struct {
	Size        uint32
	Error       uint16
	Payload     uint8
	Channel     uint8
	Acquisition time.Time
	Reception   time.Time
}

func (h *HRDLHeader) UnmarshalBinary(bs []byte) error {
	if h == nil {
		h = new(HRDLHeader)
	}
	var (
		coarse uint32
		fine   uint8
	)
	r := bytes.NewReader(bs)
	binary.Read(r, binary.LittleEndian, &h.Size)
	binary.Read(r, binary.BigEndian, &h.Error)
	binary.Read(r, binary.BigEndian, &h.Payload)
	binary.Read(r, binary.BigEndian, &h.Channel)

	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)
	h.Acquisition = readTime5(coarse, fine)

	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)
	h.Reception = readTime5(coarse, fine)

	return nil
}

type VMUHeader struct {
	Word        uint32
	Size        uint32
	Origin      uint8
	Channel     uint8
	Sequence    uint32
	Acquisition time.Time
}

func (v *VMUHeader) UnmarshalBinary(bs []byte) error {
	if v == nil {
		v = new(VMUHeader)
	}
	var (
		spare  uint16
		coarse uint32
		fine   uint16
	)

	r := bytes.NewReader(bs)
	binary.Read(r, binary.LittleEndian, &v.Word)
	binary.Read(r, binary.LittleEndian, &v.Size)
	binary.Read(r, binary.LittleEndian, &v.Channel)
	binary.Read(r, binary.LittleEndian, &v.Origin)
	binary.Read(r, binary.LittleEndian, &spare)
	binary.Read(r, binary.LittleEndian, &v.Sequence)
	binary.Read(r, binary.LittleEndian, &coarse)
	binary.Read(r, binary.LittleEndian, &fine)
	binary.Read(r, binary.LittleEndian, &spare)

	v.Acquisition = readTime6(coarse, fine)

	return nil
}

type VMUPacket struct {
	HRH     *HRDLHeader
	VMU     *VMUHeader
	Payload []byte
}

func DecodeVMU() Decoder {
	f := func(bs []byte) (Packet, error) {
		if len(bs) < HRDLHeaderLen+VMUHeaderLen {
			return nil, io.ErrShortBuffer
		}
		var (
			h HRDLHeader
			v VMUHeader
		)
		if err := h.UnmarshalBinary(bs); err != nil {
			return nil, err
		}
		if err := v.UnmarshalBinary(bs[HRDLHeaderLen:]); err != nil {
			return nil, err
		}
		p := VMUPacket{
			HRH:     &h,
			VMU:     &v,
			Payload: bs,
		}
		return &p, nil
	}
	return DecoderFunc(f)
}

func (v *VMUPacket) Error() bool {
	return v.HRH.Error != 0
}

func (v *VMUPacket) PacketInfo() *Info {
	return &Info{
		Id:       int(v.VMU.Channel),
		Sequence: int(v.VMU.Sequence),
		Size:     len(v.Payload) - HRDLHeaderLen,
		AcqTime:  v.VMU.Acquisition,
		Sum:      adler32.Checksum(v.Payload[HRDLHeaderLen:]),
	}
}

func (v *VMUPacket) Timestamp() time.Time {
	return v.VMU.Acquisition
}

func (v *VMUPacket) Reception() time.Time {
	return v.HRH.Acquisition
}

func (v *VMUPacket) Id() (int, int) {
	return int(v.VMU.Channel), int(v.VMU.Origin)
}

func (v *VMUPacket) Sequence() int {
	return int(v.VMU.Sequence)
}

func (v *VMUPacket) Len() int {
	return len(v.Payload)
}

func (v *VMUPacket) Less(p Packet) bool {
	o, ok := p.(*VMUPacket)
	if !ok {
		return ok
	}
	if v.VMU.Channel == o.VMU.Channel {
		return v.VMU.Sequence < o.VMU.Sequence
	}
	return v.VMU.Size < o.VMU.Size
}

func (v *VMUPacket) Diff(o Packet) *Gap {
	u, ok := o.(*VMUPacket)
	if o == nil || !ok {
		return nil
	}
	if u.VMU.Acquisition.After(v.VMU.Acquisition) {
		return u.Diff(v)
	}
	if u.VMU.Channel != v.VMU.Channel || u.VMU.Sequence+1 == v.VMU.Sequence {
		return nil
	}
	return &Gap{
		Id:     int(u.VMU.Channel),
		Starts: u.VMU.Acquisition,
		Ends:   v.VMU.Acquisition,
		Last:   int(u.VMU.Sequence),
		First:  int(v.VMU.Sequence),
	}
}

func (v *VMUPacket) Bytes() []byte {
	return v.Payload
}

func (v *VMUPacket) Valid() bool {
	var sum uint32

	i := HRDLHeaderLen + 8
	j := len(v.Payload) - binary.Size(sum)

	for _, b := range v.Payload[i:j] {
		sum += uint32(b)
	}
	return sum == binary.LittleEndian.Uint32(v.Payload[j:])
}

type Index struct {
	Id        int
	Offset    int
	Sequence  int
	Size      int
	Timestamp time.Time

	Sum string
}

type Reader struct {
	scan    *bufio.Scanner
	decoder Decoder
	digest  hash.Hash

	queue chan Packet
}

func NewReader(r io.Reader, d Decoder) *Reader {
	rs := &Reader{decoder: d, digest: md5.New()}
	rs.Reset(r)
	return rs
}

func (r *Reader) Reset(rs io.Reader) {
	r.digest.Reset()
	r.scan = Scan(io.TeeReader(rs, r.digest))
}

func (r *Reader) IndexSum() ([]*Index, string) {
	return r.indexSum()
}

func (r *Reader) Index() []*Index {
	ix, _ := r.indexSum()
	return ix
}

func (r *Reader) indexSum() ([]*Index, string) {
	var (
		is   []*Index
		curr int
	)
	for p := range r.Packets() {
		id, _ := p.Id()
		i := Index{
			Id:        id,
			Offset:    curr,
			Timestamp: p.Timestamp(),
			Sequence:  p.Sequence(),
			Size:      p.Len(),
		}
		curr += i.Size
		is = append(is, &i)
	}
	return is, fmt.Sprintf("%x", r.digest.Sum(nil))
}

func (r *Reader) Gaps() <-chan *Gap {
	queue := make(chan *Gap)
	go func() {
		defer close(queue)
		gs := make(map[int]Packet)
		for curr := range r.Packets() {
			id, _ := curr.Id()
			prev, ok := gs[id]
			if ok {
				if prev.Sequence()+1 != curr.Sequence() {
					g := Gap{
						Id:     id,
						Starts: prev.Timestamp(),
						Ends:   curr.Timestamp(),
						Last:   prev.Sequence(),
						First:  curr.Sequence(),
					}
					queue <- &g
				}
			}
			gs[id] = curr
		}
	}()
	return queue
}

func (r *Reader) Next() (Packet, error) {
	if !r.scan.Scan() {
		return nil, io.EOF
	}
	bs := r.scan.Bytes()
	if err := r.scan.Err(); err != nil {
		return nil, err
	}
	if r.decoder.Decode == nil {
		return nil, ErrSkip
	}
	return r.decoder.Decode(bs)
}

func (r *Reader) Packets() <-chan Packet {
	if r.queue == nil {
		r.queue = make(chan Packet)
		go r.packets()
	}
	return r.queue
}

func (r *Reader) packets() {
	defer close(r.queue)
	for {
		p, err := r.Next()
		if err == io.EOF {
			return
		}
		if err == nil {
			r.queue <- p
		}
	}
}

type scanner struct {
	io.Closer
	*bufio.Scanner
}

func ScanFile(f string) (ScanCloser, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	return &scanner{Closer: r, Scanner: Scan(r)}, nil
}

func Scan(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1<<20), MaxBufferSize)
	s.Split(scanPackets)

	return s
}

func scanPackets(bs []byte, ateof bool) (int, []byte, error) {
	if len(bs) < 4 {
		return 0, nil, nil
	}
	size := int(binary.LittleEndian.Uint32(bs))

	if len(bs) < size+4 {
		return 0, nil, nil
	}
	vs := make([]byte, size+4)
	return copy(vs, bs[:size+4]), vs, nil
}

func readTime5(coarse uint32, fine uint8) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 256.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}

func readTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}
