package main

import (
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func NewPrinter(f string) (Printer, error) {
	var (
		p   Printer
		err error
	)
	switch strings.ToLower(f) {
	case "":
		p = &logPrinter{logger: log.New(os.Stdout, "", 0)}
	case "csv":
		c := csv.NewWriter(os.Stdout)
		p = &csvPrinter{c}
	default:
		err = fmt.Errorf("unsupported output format")
	}
	return p, err
}

type Flusher interface {
	Flush() error
}

type Printer interface {
	Print(Packet, time.Duration) error
}

type logPrinter struct {
	logger *log.Logger
	last   Packet
}

func (pt *logPrinter) Print(p Packet, delta time.Duration) error {
	switch p := p.(type) {
	case *VMUPacket:
		printVMUPacket(pt.logger, p, p.Diff(pt.last), delta)
	case *TMPacket:
		printTMPacket(pt.logger, p, p.Diff(pt.last), delta)
	case *PDPacket:
		printPDPacket(pt.logger, p, delta)
	}
	pt.last = p
	return nil
}

type csvPrinter struct {
	writer *csv.Writer
}

func (c *csvPrinter) Flush() error {
	c.writer.Flush()
	return c.writer.Error()
}

func (c *csvPrinter) Print(p Packet, delta time.Duration) error {
	var row []string
	switch p := p.(type) {
	case *VMUPacket:
		row = []string{
			strconv.Itoa(p.Sequence()),
			strconv.Itoa(p.Len()),
			strconv.FormatUint(uint64(p.HRH.Error), 10),
			strconv.FormatUint(uint64(p.HRH.Payload), 10),
			p.VMU.Channel.String(),
			strconv.FormatUint(uint64(p.VMU.Origin), 10),
			p.HRH.Acquisition.Add(delta).Format(TimeFormat),
			p.HRH.Reception.Add(delta).Format(TimeFormat),
			fmt.Sprintf("%x", md5.Sum(p.Payload)),
		}
	case *TMPacket:
		row = []string{
			strconv.Itoa(p.CCSDS.Sequence()),
			strconv.Itoa(p.Len()),
			strconv.Itoa(p.CCSDS.Apid()),
			p.ESA.Acquisition.Add(delta).Format(TimeFormat),
			p.PTH.Reception.Add(delta).Format(TimeFormat),
			fmt.Sprintf("%x", md5.Sum(p.Payload)),
		}
	case *PDPacket:
		row = []string{
			p.Timestamp().Format(TimeFormat),
			fmt.Sprintf("%x", p.UMI.Code),
			p.UMI.State.String(),
			p.UMI.Type.String(),
			strconv.Itoa(p.Len()),
			fmt.Sprintf("%x", p.Payload[len(p.Payload)-int(p.UMI.Len):]),
			fmt.Sprintf("%x", md5.Sum(p.Payload)),
		}
	}
	return c.writer.Write(row)
}

func printVMUPacket(logger *log.Logger, p *VMUPacket, g *Gap, delta time.Duration) {
	const row = "%9d | %04x || %s | %9d | %6d | %s | %5s || %02x | %s | %9d | %16s | %08x | %08x | %3s || %x | %s"

	a := p.HRH.Acquisition.Add(delta).Format(TimeFormat)
	x := p.HRH.Reception.Sub(p.HRH.Acquisition)

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
	q := v.Acquisition().Format(TimeFormat)
	var diff int
	if g != nil {
		diff = g.Missing()
	}
	sum := md5.Sum(p.Payload)
	bad := "-"
	if p.Sum != p.Control {
		bad = "bad"
	}
	logger.Printf(row, p.Len(), p.HRH.Error, a, p.Sequence(), diff, rt, p.VMU.Channel, v.Origin, q, v.Sequence(), v.String(), p.Sum, p.Control, bad, sum, x)
}

func printTMPacket(logger *log.Logger, p *TMPacket, g *Gap, delta time.Duration) {
	const row = "%9d | %4d | %4d | %4d || %s | %s | %16s | %x || %s"
	a := p.Timestamp().Add(delta).Format(TimeFormat)
	r := p.Reception().Add(delta).Format(TimeFormat)

	x := p.Reception().Sub(p.Timestamp())
	var diff int
	if g != nil {
		diff = g.Missing()
	}
	logger.Printf(row, p.Sequence(), diff, p.Len(), p.CCSDS.Apid(), a, r, p.ESA.PacketType(), md5.Sum(p.Bytes()), x)
}

func printPDPacket(logger *log.Logger, p *PDPacket, delta time.Duration) {
	const row = "%s | %10s | 0x%012x | %08x | %3d | %10s | % x"
	a := p.Timestamp().Add(delta).Format(TimeFormat)
	ds := p.Payload[len(p.Payload)-int(p.UMI.Len):]
	if len(ds) > 16 {
		ds = ds[:16]
	}
	logger.Printf(row, a, p.UMI.State, p.UMI.Code, p.UMI.Orbit, p.UMI.Len, p.UMI.Type, ds)
}
