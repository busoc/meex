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
		p = logPrinter{logger: log.New(os.Stdout, "", 0)}
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
}

func (pt logPrinter) Print(p Packet, delta time.Duration) error {
	switch p := p.(type) {
	case *VMUPacket:
		printVMUPacket(pt.logger, p, delta)
	case *TMPacket:
		printTMPacket(pt.logger, p, delta)
	case *PDPacket:
		printPDPacket(pt.logger, p, delta)
	}
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
		var channel string
		switch p.VMU.Channel {
		case 1, 2:
			channel = fmt.Sprintf("vic%d", p.VMU.Channel)
		case 3:
			channel = "lrsd"
		}
		row = []string{
			strconv.Itoa(p.Sequence()),
			strconv.Itoa(p.Len()),
			strconv.FormatUint(uint64(p.HRH.Error), 10),
			strconv.FormatUint(uint64(p.HRH.Payload), 10),
			channel,
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

func printVMUPacket(logger *log.Logger, p *VMUPacket, delta time.Duration) {
	const row = "%9d | %8d | %04x | %02x | %5s | %02x | %s | %s | %x | %s"

	a := p.HRH.Acquisition.Add(delta).Format(TimeFormat)
	r := p.HRH.Reception.Add(delta).Format(TimeFormat)

	x := p.HRH.Reception.Sub(p.HRH.Acquisition)
	channel, origin := p.Id()

	var name string
	switch channel {
	case 1, 2:
		name = fmt.Sprintf("vic%d", channel)
	case 3:
		name = "lrsd"
	}
	logger.Printf(row, p.Sequence(), p.Len(), p.HRH.Error, p.HRH.Payload, name, origin, a, r, md5.Sum(p.Bytes()), x)
}

func printTMPacket(logger *log.Logger, p *TMPacket, delta time.Duration) {
	const row = "%9d | %4d | %4d | %s | %s | %x | %s"
	a := p.Timestamp().Add(delta).Format(TimeFormat)
	r := p.Reception().Add(delta).Format(TimeFormat)

	x := p.Reception().Sub(p.Timestamp())
	logger.Printf(row, p.Sequence(), p.Len(), p.CCSDS.Apid(), a, r, md5.Sum(p.Bytes()), x)
}

func printPDPacket(logger *log.Logger, p *PDPacket, delta time.Duration) {
	const row = "%s | %10s | %x | %x | %3d | %10s | % x"
	a := p.Timestamp().Add(delta).Format(TimeFormat)
	ds := p.Payload[len(p.Payload)-int(p.UMI.Len):]
	if len(ds) > 16 {
		ds = ds[:16]
	}
	logger.Printf(row, a, p.UMI.State, p.UMI.Code, p.UMI.Orbit, p.UMI.Len, p.UMI.Type, ds)
}
