package main

import (
	"log"
	"time"

	"github.com/midbel/cli"
)

const TimeFormat = "2006-01-02 15:04:05.000"

var countCommand = &cli.Command{
	Usage: "count [-k type] [-g gps-time] <file...>",
	Short: "count packets available into RT file(s)",
	Run:   runCount,
}

var listCommand = &cli.Command{
	Usage: "list [-e with-invalid] [-f format] [-k type] [-g gps-time] [-i pid] <file...>",
	Alias: []string{"ls"},
	Short: "list packets present into RT file(s)",
	Run:   runList,
}

var diffCommand = &cli.Command{
	Usage: "diff [-g gps-time] [-k type] [-d duration] <file...>",
	Alias: []string{"show-gaps"},
	Short: "report missing packets in RT file(s)",
	Run:   runDiff,
}

var errCommand = &cli.Command{
	Usage: "verify [-k type] <file...>",
	Alias: []string{"check"},
	Short: "report error in packets found in RT file(s)",
	Run:   runError,
}

func runList(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	format := cmd.Flag.String("f", "", "format")
	id := cmd.Flag.Int("i", 0, "")
	toGPS := cmd.Flag.Bool("g", false, "gps time")
	erronly := cmd.Flag.Bool("e", false, "include invalid packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	pt, err := NewPrinter(*format)
	if err != nil {
		return err
	}
	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}
	queue := Walk(cmd.Flag.Args(), DecodeById(*id, kind.Decod))
	var size, total uint64
	n := time.Now()
	for p := range queue {
		if !*erronly && p.Error() {
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
	duration := cmd.Flag.Duration("d", 0, "duration")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}
	const row = "%20s | %s | %s | %6d | %6d | %8d | %s"

	var (
		count   uint64
		missing uint64
		// size    uint64
		elapsed time.Duration
	)

	for g := range Gaps(cmd.Flag.Args(), kind.Decod) {
		count++
		missing += uint64(g.Missing())
		elapsed += g.Duration()

		if g.Duration() >= *duration {
			p := g.Starts.Add(delta).Format(TimeFormat)
			c := g.Ends.Add(delta).Format(TimeFormat)

			log.Printf(row, g.Key, p, c, g.Last, g.First, g.Missing(), g.Duration())
		}
	}
	log.Printf("%d gaps found (%d missing packets - %s)", count, missing, elapsed)
	return nil
}

func runError(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
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
	log.Printf("%d errors found (%d packets, %s)", err, total, elapsed)
	return nil
}

func runCount(cmd *cli.Command, args []string) error {
	const row = "%20s | %20s | %8d | %8d | %8dMB | %8d"

	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	toGPS := cmd.Flag.Bool("g", false, "to gps time")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}

	var z Coze
	now := time.Now()
	for c := range CountByDay(cmd.Flag.Args(), kind.Decod) {
		z.Update(c.Coze)
		log.Printf(row, c.When.Add(delta).Format("2006-01-02"), c.Key, c.Count, c.Missing, c.Size>>20, c.Error)
	}
	log.Printf("%d packets found, %d missing (%dMB, %s)", z.Count, z.Missing, z.Size>>20, time.Since(now))
	return nil
}
