package main

import (
	"log"
	"strconv"
	"time"

	"github.com/midbel/cli"
)

const TimeFormat = "2006-01-02 15:04:05.000"

var countCommand = &cli.Command{
	Usage: "count [-k] [-g] [-x] <rt,...>",
	Short: "count packets available into RT file(s)",
	Run:   runCount,
}

var listCommand = &cli.Command{
	Usage: "list [-f] [-k] [-g] [-i] <rt,...>",
	Alias: []string{"ls"},
	Short: "list packets present into RT file(s)",
	Run:   runList,
}

var diffCommand = &cli.Command{
	Usage: "diff [-g] [-k] [-x] [-d] <rt,...>",
	Alias: []string{"gaps"},
	Short: "report missing packets in RT file(s)",
	Run:   runDiff,
}

var errCommand = &cli.Command{
	Usage: "verify [-k] [-g] <rt,...>",
	Short: "report error in packets found in RT file(s)",
	Run:   runError,
}

func runList(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	format := cmd.Flag.String("f", "", "format")
	id := cmd.Flag.Int("i", 0, "")
	toGPS := cmd.Flag.Bool("g", false, "gps time")
	erronly := cmd.Flag.Bool("e", false, "error only")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	pt, err := NewPrinter(*format)
	if err != nil {
		return err
	}
	if f, ok := pt.(Flusher); ok {
		defer f.Flush()
	}
	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}
	queue := Walk(cmd.Flag.Args(), DecodeById(*id, kind.Decod))
	var size, total uint64
	n := time.Now()
	for p := range queue {
		if *erronly && !p.Error() {
			continue
		}
		total++
		size += uint64(p.Len())
		if err := pt.Print(p, delta); err != nil {
			return err
		}
	}
	log.Printf("%d packets found %s (%dMB)", total, time.Since(n), size>>20)
	return nil
}

func runDiff(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	toGPS := cmd.Flag.Bool("g", false, "gps time")
	toHex := cmd.Flag.Bool("x", false, "to hex")
	duration := cmd.Flag.Duration("d", 0, "duration")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}
	base := 10
	if *toHex {
		base = 16
	}
	const row = "%5s | %s | %s | %6d | %6d | %8d | %s"

	var (
		count   uint64
		missing uint64
		size    uint64
		elapsed time.Duration
	)

	gs := make(map[int]Packet)
	for curr := range Walk(cmd.Flag.Args(), kind.Decod) {
		count++
		size += uint64(curr.Len())

		id, _ := curr.Id()
		if g := curr.Diff(gs[id]); g != nil {
			missing += uint64(g.Missing())
			elapsed += g.Duration()

			if g.Duration() >= *duration {
				p := g.Starts.Add(delta).Format(TimeFormat)
				c := g.Ends.Add(delta).Format(TimeFormat)

				id := strconv.FormatInt(int64(g.Id), base)
				log.Printf(row, id, p, c, g.Last, g.First, g.Missing(), g.Duration())
			}
		}
		gs[id] = curr
	}
	log.Printf("%d packets found (%dMB) - missing: %d (time: %s)", count, size>>20, missing, elapsed)
	return nil
}

func runError(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	// aggr := cmd.Flag.String("g", "", "aggregate")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var err, total uint64
	cs := make(map[uint64]uint64)

	n := time.Now()
	for p := range Walk(cmd.Flag.Args(), kind.Decod) {
		total++
		if !p.Error() {
			continue
		}
		err++

		switch p := p.(type) {
		default:
		case *VMUPacket:
			cs[uint64(p.HRH.Error)]++
		case *PDPacket:
			cs[uint64(p.UMI.Orbit)]++
		}
	}
	elapsed := time.Since(n)
	for e, c := range cs {
		log.Printf("%04x: %8d", e, c)
	}
	log.Printf("%d/%d errors found (%s)", err, total, elapsed)
	return nil
}

func runCount(cmd *cli.Command, args []string) error {
	const row = "%s | %5s | %8d | %8d | %8dMB | %8d"

	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	toGPS := cmd.Flag.Bool("g", false, "to gps time")
	toHex := cmd.Flag.Bool("x", false, "to hex")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}
	base := 10
	if *toHex {
		base = 16
	}

	var z Coze
	now := time.Now()
	for c := range CountByDay(cmd.Flag.Args(), kind.Decod) {
		z.Update(c.Coze)
		id := strconv.FormatInt(int64(c.Id), base)
		log.Printf(row, c.When.Add(delta).Format("2006-01-02"), id, c.Count, c.Missing, c.Size>>20, c.Error)
	}
	log.Printf("%d packets found, %d missing (%dMB, %s)", z.Count, z.Missing, z.Size>>20, time.Since(now))
	return nil
}
