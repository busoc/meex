package main

import (
	"bufio"
	"bytes"
	// "crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/busoc/timutil"
	"github.com/midbel/xxh"
)

var ErrShortBuffer = errors.New("need more bytes")

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

var (
	UNIX = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	GPS  = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
)

type byId struct {
	id    int
	inner Decoder
}

func DecodeById(id int, d Decoder) Decoder {
	return &byId{id, d}
}

func (i *byId) Decode(bs []byte) (Packet, error) {
	// if i.inner.Decode == nil {
	if i.inner == nil {
		return nil, ErrSkip
	}
	p, err := i.inner.Decode(bs)
	if err != nil {
		return p, err
	}
	if i.id > 0 {
		id, _ := p.Id()
		if id != i.id {
			return nil, ErrSkip
		}
	}
	return p, nil
}

type DecoderFunc func([]byte) (Packet, error)

func (d DecoderFunc) Decode(bs []byte) (Packet, error) {
	return d(bs)
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
	if len(bs) < UMIHeaderLen {
		return ErrShortBuffer
	}
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

	u.Acquisition = timutil.Join5(coarse, fine)
	return nil
}

type PDPacket struct {
	UMI     *UMIHeader
	Payload []byte
}

func DecodePD() Decoder {
	f := func(bs []byte) (Packet, error) {
		if len(bs) < UMIHeaderLen {
			return nil, ErrShortBuffer
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
	code, _ := p.Id()
	return &Info{
		Id:      code,
		Size:    len(p.Payload) - UMIHeaderLen,
		AcqTime: p.Timestamp(),
		Sum:     adler32.Checksum(p.Payload[UMIHeaderLen:]),
		Type:    "pp",
	}
}

func (p *PDPacket) Timestamp() time.Time {
	return p.UMI.Acquisition
}

func (p *PDPacket) Reception() time.Time {
	return p.UMI.Acquisition
}

func (p *PDPacket) Id() (int, int) {
	high := uint64(binary.BigEndian.Uint16(p.UMI.Code[:2])) << 32
	low := uint64(binary.BigEndian.Uint32(p.UMI.Code[2:]))
	return int(high | low), int(p.UMI.Code[0])
}

func (p *PDPacket) Sequence() int {
	return 0
}

func (p *PDPacket) Len() int {
	return len(p.Payload)
}

func (p *PDPacket) Less(o Packet) bool {
	if p.Timestamp().Before(o.Timestamp()) {
		return true
	}
	pc, _ := p.Id()
	oc, _ := p.Id()
	return pc < oc
}

func (p *PDPacket) Diff(o Packet) *Gap {
	if _, ok := o.(*PDPacket); o == nil || !ok {
		return nil
	}
	pc, _ := p.Id()
	oc, _ := p.Id()
	if pc != oc {
		return nil
	}
	if o.Timestamp().After(p.Timestamp()) {
		return o.Diff(p)
	}
	delta := p.Timestamp().Sub(o.Timestamp())
	if delta <= time.Second {
		return nil
	}
	return &Gap{
		Id:     pc,
		Starts: o.Timestamp(),
		Ends:   p.Timestamp(),
	}
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
	if len(bs) < PTHHeaderLen {
		return ErrShortBuffer
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

	p.Reception = timutil.Join5(coarse, fine)

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

type ESAPacketType uint8

const (
	Default ESAPacketType = iota
	DataDump
	DataSegment
	EssentialHk
	SystemHk
	PayloadHk
	ScienceData
	AncillaryData
	EssentialCmd
	SystemCmd
	PayloadCmd
	DataLoad
	Response
	Report
	Exception
	Acknowledge
)

func (e ESAPacketType) Type() string {
	switch e >> 2 {
	default:
		return "***"
	case 0, 1:
		return "dat"
	case 2:
		return "cmd"
	case 3:
		return "evt"
	}
}

func (e ESAPacketType) String() string {
	switch e {
	default:
		return "***"
	case DataDump:
		return "data dump"
	case DataSegment:
		return "data segment"
	case EssentialHk:
		return "essential hk"
	case SystemHk:
		return "system hk"
	case PayloadHk:
		return "payload hk"
	case ScienceData:
		return "science data"
	case AncillaryData:
		return "ancillary data"
	case EssentialCmd:
		return "essential cmd"
	case SystemCmd:
		return "system cmd"
	case PayloadCmd:
		return "payload cmd"
	case DataLoad:
		return "data load"
	case Response:
		return "response"
	case Report:
		return "report"
	case Exception:
		return "exception"
	case Acknowledge:
		return "acknowledge"
	}
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
	if len(bs) < ESAHeaderLen {
		return ErrShortBuffer
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

	e.Acquisition = timutil.Join5(coarse, fine)

	return nil
}

func (e *ESAHeader) PacketType() ESAPacketType {
	return ESAPacketType(e.Info & 0xF)
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
			return nil, ErrShortBuffer
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
		Context:  t.ESA.PacketType().String(),
		Type:     "tm",
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
	if p, ok := o.(*TMPacket); o == nil || !ok || t.CCSDS.Apid() != p.CCSDS.Apid() {
		return nil
	}

	if o.Timestamp().After(t.Timestamp()) {
		return o.Diff(t)
	}
	if delta := (t.Sequence() - o.Sequence()) & 0x3FFF; delta <= 1 {
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
	if len(bs) < HRDLHeaderLen {
		return ErrShortBuffer
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
	h.Acquisition = timutil.Join5(coarse, fine)

	binary.Read(r, binary.BigEndian, &coarse)
	binary.Read(r, binary.BigEndian, &fine)
	h.Reception = timutil.Join5(coarse, fine)

	return nil
}

type VMUChannel uint8

const (
	ChannelVic1 VMUChannel = iota + 1
	ChannelVic2
	ChannelLRSD
)

func (v VMUChannel) String() string {
	switch v {
	default:
		return "***"
	case ChannelVic1, ChannelVic2:
		return "vic" + fmt.Sprint(int(v))
	case ChannelLRSD:
		return "lrsd"
	}
}

type VMUCommonHeader struct {
	Property uint8
	Origin   uint8
	AcqTime  time.Duration
	AuxTime  time.Duration
	Stream   uint16
	Counter  uint32
	UPI      [32]byte

	Valid bool
}

func (v *VMUCommonHeader) Id() (int, int) {
	return int(v.Origin), int(v.Property >> 4)
}

func (v *VMUCommonHeader) Sequence() int {
	return int(v.Counter)
}

func (v *VMUCommonHeader) Diff(p Packet) *Gap {
	var o *VMUCommonHeader
	switch p := p.(type) {
	case *Table:
		o = p.VMUCommonHeader
	case *Image:
		o = p.VMUCommonHeader
	default:
		return nil
	}
	if !(o.Origin == v.Origin && o.Property>>4 == v.Property>>4) {
		return nil
	}
	if o.Timestamp().After(v.Timestamp()) {
		return o.Diff(p)
	}
	if o.Counter == v.Counter || o.Counter+1 == v.Counter {
		return nil
	}
	return &Gap{
		Id:     int(v.Origin),
		Starts: o.Timestamp(),
		Ends:   v.Timestamp(),
		Last:   int(o.Counter),
		First:  int(v.Counter),
	}
}

func (v *VMUCommonHeader) Timestamp() time.Time {
	return v.Acquisition()
}

func (v *VMUCommonHeader) Reception() time.Time {
	return v.Acquisition()
}

func (v *VMUCommonHeader) Error() bool {
	return !v.Valid
}

func (v *VMUCommonHeader) Less(o Packet) bool {
	return v.Timestamp().Before(o.Timestamp())
}

func (v *VMUCommonHeader) Acquisition() time.Time {
	return GPS.Add(v.AcqTime)
}

func (v *VMUCommonHeader) Auxiliary() time.Time {
	return GPS.Add(v.AcqTime)
}

func (v *VMUCommonHeader) String() string {
	bs := bytes.Trim(v.UPI[:], "\x00")
	if len(bs) > 0 {
		return strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				return r
			}
			return '*'
		}, string(bs))
	}
	return v.Type()
}

func (v *VMUCommonHeader) Type() string {
	switch v.Property >> 4 {
	case 1:
		return "SCC"
	case 2:
		return "IMG"
	default:
		return "UNKNOWN"
	}
}

type VMUImageHeader struct {
	Format  uint8
	Pixels  uint32
	Region  uint64
	Drop    uint16
	Scaling uint32
	Force   uint8
}

type Image struct {
	*VMUCommonHeader
	*VMUImageHeader
	Payload []byte
}

func decodeImage(bs []byte, valid bool) (*Image, error) {
	r := bytes.NewReader(bs)
	var (
		c VMUCommonHeader
		s VMUImageHeader
	)

	binary.Read(r, binary.LittleEndian, &c.Property)
	binary.Read(r, binary.LittleEndian, &c.Stream)
	binary.Read(r, binary.LittleEndian, &c.Counter)
	binary.Read(r, binary.LittleEndian, &c.AcqTime)
	binary.Read(r, binary.LittleEndian, &c.AuxTime)
	binary.Read(r, binary.LittleEndian, &c.Origin)

	binary.Read(r, binary.LittleEndian, &s.Format)
	binary.Read(r, binary.LittleEndian, &s.Pixels)
	binary.Read(r, binary.LittleEndian, &s.Region)
	binary.Read(r, binary.LittleEndian, &s.Drop)
	binary.Read(r, binary.LittleEndian, &s.Scaling)
	binary.Read(r, binary.LittleEndian, &s.Force)

	if _, err := io.ReadFull(r, c.UPI[:]); err != nil {
		return nil, err
	}
	c.Valid = valid

	i := Image{
		VMUCommonHeader: &c,
		VMUImageHeader:  &s,
		Payload:         bs,
	}
	return &i, nil
}

func (i *Image) PacketInfo() *Info {
	return &Info{
		Id:       int(i.Origin),
		Sequence: i.Sequence(),
		Size:     len(i.Payload) - VMUHeaderLen - HRDLHeaderLen,
		AcqTime:  i.Acquisition(),
		Sum:      0,
		Context:  i.String(),
		Type:     "hrd",
	}
}

func (i *Image) Len() int {
	return len(i.Payload)
}

func (i *Image) Bytes() []byte {
	return i.Payload
}

func (i *Image) Export(w io.Writer) error {
	return nil
}

type Table struct {
	*VMUCommonHeader
	Payload []byte
}

func decodeTable(bs []byte, valid bool) (*Table, error) {
	r := bytes.NewReader(bs)

	var c VMUCommonHeader
	binary.Read(r, binary.LittleEndian, &c.Property)
	binary.Read(r, binary.LittleEndian, &c.Stream)
	binary.Read(r, binary.LittleEndian, &c.Counter)
	binary.Read(r, binary.LittleEndian, &c.AcqTime)
	binary.Read(r, binary.LittleEndian, &c.AuxTime)
	binary.Read(r, binary.LittleEndian, &c.Origin)

	if _, err := io.ReadFull(r, c.UPI[:]); err != nil {
		return nil, err
	}
	c.Valid = valid

	t := Table{
		VMUCommonHeader: &c,
		Payload:         bs,
	}
	return &t, nil
}

func (t *Table) PacketInfo() *Info {
	return &Info{
		Id:       int(t.Origin),
		Sequence: t.Sequence(),
		Size:     len(t.Payload) - VMUHeaderLen - HRDLHeaderLen,
		AcqTime:  t.Acquisition(),
		Sum:      0,
		Context:  t.String(),
		Type:     "hrd",
	}
}

func (t *Table) Len() int {
	return len(t.Payload)
}

func (t *Table) Bytes() []byte {
	return t.Payload
}

func (t *Table) Export(w io.Writer) error {
	return nil
}

type VMUHeader struct {
	Word        uint32
	Size        uint32
	Origin      uint8
	Channel     VMUChannel
	Sequence    uint32
	Acquisition time.Time
}

func (v *VMUHeader) UnmarshalBinary(bs []byte) error {
	if v == nil {
		v = new(VMUHeader)
	}
	if len(bs) < VMUHeaderLen {
		return ErrShortBuffer
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

	v.Acquisition = timutil.Join6(coarse, fine)

	return nil
}

type VMUPacket struct {
	HRH     *HRDLHeader
	VMU     *VMUHeader
	Payload []byte
	Sum     uint32
	Control uint32
}

func DecodeVMU() Decoder {
	return DecoderFunc(decodeVMU)
}

func DecodeHRD() Decoder {
	f := func(bs []byte) (Packet, error) {
		p, err := decodeVMU(bs)
		if err != nil {
			return nil, err
		}
		v, ok := p.(*VMUPacket)
		if !ok {
			return nil, fmt.Errorf("can not decode VMU packet")
		}
		return v.Data()
	}
	return DecoderFunc(f)
}

func decodeVMU(bs []byte) (Packet, error) {
	if len(bs) < HRDLHeaderLen+VMUHeaderLen {
		return nil, ErrShortBuffer
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
		Sum:     binary.LittleEndian.Uint32(bs[len(bs)-4:]),
	}
	for i := HRDLHeaderLen + 8; i < len(bs)-4; i++ {
		p.Control += uint32(bs[i])
	}

	return &p, nil
}

func (v *VMUPacket) Data() (HRPacket, error) {
	var (
		d   HRPacket
		err error
	)
	switch valid := v.Control == v.Sum; v.VMU.Channel {
	default:
	case ChannelVic1, ChannelVic2:
		d, err = decodeImage(v.Payload[HRDLHeaderLen+VMUHeaderLen:], valid)
	case ChannelLRSD:
		d, err = decodeTable(v.Payload[HRDLHeaderLen+VMUHeaderLen:], valid)
	}
	return d, err
}

func (v *VMUPacket) Error() bool {
	if v.HRH.Error != 0 {
		return true
	}
	return v.Sum != v.Control
}

func (v *VMUPacket) PacketInfo() *Info {
	return &Info{
		Id:       int(v.VMU.Channel),
		Sequence: int(v.VMU.Sequence),
		Size:     len(v.Payload) - HRDLHeaderLen,
		AcqTime:  v.VMU.Acquisition,
		Sum:      adler32.Checksum(v.Payload[HRDLHeaderLen:]),
		Type:     "vmu",
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
	if u.VMU.Channel != v.VMU.Channel || u.VMU.Sequence == v.VMU.Sequence || u.VMU.Sequence+1 == v.VMU.Sequence {
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
	// scan    *bufio.Scanner
	// reader *bufio.Reader

	reader  io.Reader
	decoder Decoder
	digest  hash.Hash

	tmp    []byte
	buffer []byte
	offset int

	queue chan Packet
}

const maxBufferSize = 32 << 20

func NewReader(r io.Reader, d Decoder) *Reader {
	rs := &Reader{
		decoder: d,
		digest:  xxh.New64(0),
		buffer:  make([]byte, maxBufferSize),
	}
	rs.Reset(r)
	return rs
}

func (r *Reader) Reset(rs io.Reader) {
	r.digest.Reset()
	r.reader = io.TeeReader(rs, r.digest)
	// r.reader = rs
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
	if diff := maxBufferSize - r.offset; diff < 1024 {
		r.offset = 0
	}
	if _, err := r.reader.Read(r.buffer[r.offset : r.offset+4]); err != nil {
		return nil, err
	}
	size := int(binary.LittleEndian.Uint32(r.buffer[r.offset:]))
	if diff := maxBufferSize - r.offset; size >= diff {
		copy(r.buffer, r.buffer[r.offset:r.offset+4])
		r.offset = 0
	}

	if _, err := r.reader.Read(r.buffer[r.offset+4 : r.offset+size+4]); err != nil {
		return nil, err
	}
	if r.decoder == nil {
		return nil, ErrSkip
	}
	offset := r.offset
	r.offset += size + 4
	return r.decoder.Decode(r.buffer[offset : offset+size+4])
}

func (r *Reader) Packets() <-chan Packet {
	if r.queue == nil {
		r.queue = make(chan Packet)
		go r.packets()
	}
	return r.queue
}

func (r *Reader) packets() {
	defer func() {
		close(r.queue)
		r.queue = nil
	}()
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

var scanBuffer = make([]byte, 4<<20)

func Scan(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(scanBuffer, MaxBufferSize)
	s.Split(scanPackets)

	return s
}

func scanPackets(bs []byte, ateof bool) (int, []byte, error) {
	if len(bs) < 4 {
		return 0, nil, nil
	}
	size := int(binary.LittleEndian.Uint32(bs)) + 4

	if len(bs) < size {
		return 0, nil, nil
	}
	vs := make([]byte, size)
	return copy(vs, bs[:size]), vs, nil
}
