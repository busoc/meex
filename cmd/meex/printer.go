package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
)

const Bad = "invalid"

func NewPrinter(f string) (*Printer, error) {
	var options []linewriter.Option
	switch strings.ToLower(f) {
	case "":
		options = append(options, linewriter.WithPadding([]byte(" ")), linewriter.WithSeparator([]byte("|")))
	case "csv":
		options = append(options, linewriter.AsCSV(false))
	default:
		return nil, fmt.Errorf("unsupported output format")
	}
	p := Printer{
		line:    linewriter.NewWriter(1024, options...),
		history: make(map[int]Packet),
	}
	return &p, nil
}

type Printer struct {
	line    *linewriter.Writer
	history map[int]Packet
}

func (pt *Printer) Print(p Packet, delta time.Duration) error {
	id, _ := p.Id()
	switch p := p.(type) {
	default:
	case *VMUPacket:
		printVMUPacket(pt.line, p, p.Diff(pt.history[id]), delta)
	case *TMPacket:
		printTMPacket(pt.line, p, p.Diff(pt.history[id]), delta)
	case *PDPacket:
		printPDPacket(pt.line, p, delta)
	}
	pt.history[id] = p
	return nil
}

func printVMUPacket(line *linewriter.Writer, p *VMUPacket, g *Gap, delta time.Duration) {
	a := p.HRH.Acquisition.Add(delta)

	hr, err := p.Data()
	if err != nil {
		return
	}
	var v *VMUCommonHeader
	switch hr := hr.(type) {
	case *Image:
		v = hr.VMUCommonHeader
	case *Table:
		v = hr.VMUCommonHeader
	default:
		return
	}
	var rt string
	if v.Origin == p.VMU.Origin {
		rt = "realtime"
	} else {
		rt = "playback"
	}
	q := v.Acquisition()
	var diff int
	if g != nil {
		diff = g.Missing()
	}
	bad := "-"
	if p.Sum != p.Control {
		bad = Bad
	}
	line.AppendUint(uint64(p.Len()), 9, linewriter.AlignRight)
	line.AppendUint(uint64(p.HRH.Error), 4, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendTime(a, TimeFormat, linewriter.AlignRight)
	line.AppendUint(uint64(p.Sequence()), 9, linewriter.AlignRight)
	line.AppendUint(uint64(diff), 6, linewriter.AlignRight)
	line.AppendString(rt, 8, linewriter.AlignRight)
	line.AppendString(p.VMU.Channel.String(), 5, linewriter.AlignRight)
	line.AppendUint(uint64(v.Origin), 2, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendTime(q, TimeFormat, linewriter.AlignRight)
	line.AppendUint(uint64(v.Sequence()), 9, linewriter.AlignRight)
	line.AppendString(v.String(), 16, linewriter.AlignRight)
	line.AppendUint(uint64(p.Sum), 8, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendUint(uint64(p.Control), 8, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendString(bad, 8, linewriter.AlignRight)
	line.AppendUint(xxh.Sum64(p.Payload, 0), 16, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendDuration(p.HRH.Reception.Sub(p.HRH.Acquisition), 9, linewriter.AlignLeft|linewriter.Millisecond)

	io.Copy(os.Stdout, line)
}

func printTMPacket(line *linewriter.Writer, p *TMPacket, g *Gap, delta time.Duration) {
	a := p.Timestamp().Add(delta)
	r := p.Reception().Add(delta)

	var diff int
	if g != nil {
		diff = g.Missing()
	}
	typ := p.ESA.PacketType()

	line.AppendUint(uint64(p.Sequence()), 9, linewriter.AlignRight)
	line.AppendUint(uint64(diff), 4, linewriter.AlignRight)
	line.AppendUint(uint64(p.Len()), 4, linewriter.AlignRight)
	line.AppendUint(uint64(p.CCSDS.Apid()), 4, linewriter.AlignRight)
	line.AppendTime(a, TimeFormat, linewriter.AlignRight)
	line.AppendTime(r, TimeFormat, linewriter.AlignRight)
	line.AppendString(typ.String(), 16, linewriter.AlignRight)
	line.AppendUint(xxh.Sum64(p.Bytes(), 0), 8, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendDuration(p.Reception().Sub(p.Timestamp()), 8, linewriter.AlignLeft|linewriter.Millisecond)

	io.Copy(os.Stdout, line)
}

func printPDPacket(line *linewriter.Writer, p *PDPacket, delta time.Duration) {
	a := p.Timestamp().Add(delta)
	ds := p.Payload[len(p.Payload)-int(p.UMI.Len):]
	if len(ds) > 16 {
		ds = ds[:16]
	}

	state := p.UMI.State.String()
	typ := p.UMI.Type.String()

	line.AppendTime(a, TimeFormat, linewriter.AlignRight)
	line.AppendString(state, 10, linewriter.AlignRight)
	line.AppendBytes(p.UMI.Code[:], 12, linewriter.AlignRight|linewriter.Hex)
	line.AppendUint(uint64(p.UMI.Orbit), 8, linewriter.AlignRight|linewriter.WithZero|linewriter.Hex)
	line.AppendUint(uint64(p.UMI.Len), 3, linewriter.AlignRight)
	line.AppendString(typ, 10, linewriter.AlignRight)
	line.AppendBytes(ds, 8, linewriter.AlignLeft|linewriter.Hex)

	io.Copy(os.Stdout, line)
}
