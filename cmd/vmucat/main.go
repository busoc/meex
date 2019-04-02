package main

import (
	"io"
	"log"
	"os"

	"github.com/busoc/rt"
	"github.com/busoc/vmu"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
	"github.com/pkg/profile"
)

const TimeFormat = "2006-01-02 15:04:05.000"

var (
	modeRT = []byte("realtime")
	modePB = []byte("playback")

	chanVic1 = []byte("vic1")
	chanVic2 = []byte("vic2")
	chanLRSD = []byte("lrsd")

	invalid = []byte("invalid")
	unknown = []byte("***")
)

var commands = []*cli.Command{
	{
		Usage: "list [-e] [-i] [-g] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff [-e] [-i] [-g] <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count [-e] [-b] [-g] <file...>",
		Short: "",
		Run:   runCount,
	},
}

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	// defer profile.Start(profile.CPUProfile).Stop()
	defer profile.Start(profile.MemProfile).Stop()
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("vrx", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}

func runList(cmd *cli.Command, args []string) error {
	keepInvalid := cmd.Flag.Bool("e", false, "invalid packet")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}

	d := vmu.NewDecoder(rt.NewReader(mr))
	line := linewriter.New(1024, 1)
	seen := make(map[uint8]vmu.Packet)

	var invalid, size, missing, skipped int
	for i := 0; ; i++ {
		p, err := d.Decode(false)
		switch err {
		case nil, vmu.ErrInvalid:
			if err == vmu.ErrInvalid {
				invalid++
				if !*keepInvalid {
					continue
				}
			}
			var diff uint32
			if prev, ok := seen[p.VMUHeader.Channel]; ok {
				diff = p.Missing(prev)
				missing += int(diff)
			}
			seen[p.VMUHeader.Channel] = p

			dumpPacket(line, p, diff, err != vmu.ErrInvalid)
			size += int(p.VMUHeader.Size)
		case vmu.ErrSkip:
      skipped++
      i--
		case io.EOF:
			log.Printf("%d packets (%dMB, %d invalid, %d missing, %d skipped)\n", i, size>>20, invalid, missing, skipped)
			return nil
		default:
			return err
		}
	}
}

func dumpPacket(line *linewriter.Writer, p vmu.Packet, missing uint32, valid bool) {
	defer line.Reset()

	h, v, c := p.HRDPHeader, p.VMUHeader, p.DataHeader

	var bad []byte
	if !valid {
		bad = invalid
	} else {
		bad = unknown
	}

	line.AppendUint(uint64(v.Size), 7, linewriter.AlignRight)
	line.AppendUint(uint64(h.Error), 4, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	// packet VMU info
	line.AppendTime(v.Timestamp(), TimeFormat, linewriter.AlignCenter)
	line.AppendUint(uint64(v.Sequence), 7, linewriter.AlignRight)
	line.AppendUint(uint64(missing), 3, linewriter.AlignRight)
	line.AppendBytes(whichMode(p.IsRealtime()), 8, linewriter.AlignCenter|linewriter.Text)
	line.AppendBytes(whichChannel(v.Channel), 4, linewriter.AlignCenter|linewriter.Text)
	// packet HRD info
	line.AppendUint(uint64(c.Origin), 2, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	line.AppendTime(c.Acquisition(), TimeFormat, linewriter.AlignCenter)
	line.AppendUint(uint64(c.Counter), 8, linewriter.AlignRight)
	line.AppendBytes(c.UserInfo(), 16, linewriter.AlignLeft|linewriter.Text)
	// packet sums and validity state
	line.AppendUint(uint64(p.Sum), 8, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	line.AppendBytes(bad, 8, linewriter.AlignCenter|linewriter.Text)
	if len(p.Data) > 0 {
		line.AppendUint(xxh.Sum64(p.Data, 0), 16, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	}
	os.Stdout.Write(append(line.Bytes(), '\n'))
}

func runDiff(cmd *cli.Command, args []string) error {
	return nil
}

func runCount(cmd *cli.Command, args []string) error {
	return nil
}

func whichChannel(c uint8) []byte {
	switch c {
	case vmu.VIC1:
		return chanVic1
	case vmu.VIC2:
		return chanVic2
	case vmu.LRSD:
		return chanLRSD
	default:
		return unknown
	}
}

func whichMode(rt bool) []byte {
	if rt {
		return modeRT
	}
	return modePB
}
