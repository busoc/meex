package main

import (
	"log"
	"time"

	"github.com/midbel/cli"
)

const TimeFormat = "2006-01-02 15:04:05.000"

var statsCommand = &cli.Command{
	Usage: "stats [-g] [-k] [-a] <rt,...>",
	Alias: []string{"report"},
	Short: "report status of packets into RT file(s)",
	Run:   runReport,
}

var listCommand = &cli.Command{
	Usage: "list [-f] [-k] [-g] [-i] <rt,...>",
	Alias: []string{"ls"},
	Short: "list packets present into RT file(s)",
	Run:   runList,
}

func runList(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	format := cmd.Flag.String("f", "", "format")
	id := cmd.Flag.Int("i", 0, "")
	toGPS := cmd.Flag.Bool("g", false, "gps time")
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
	for p := range queue {
		if err := pt.Print(p, delta); err != nil {
			return err
		}
	}
	return nil
}

func runReport(cmd *cli.Command, args []string) error {
	var kind Kind
	cmd.Flag.Var(&kind, "k", "packet type")
	toGPS := cmd.Flag.Bool("g", false, "gps time")
	aggr := cmd.Flag.Bool("a", false, "aggregate report per channel")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var delta time.Duration
	if !*toGPS {
		delta = GPS.Sub(UNIX)
	}

	queue := Walk(cmd.Flag.Args(), kind.Decod)
	if *aggr {
		reportCounts(queue)
	} else {
		reportGaps(queue, delta)
	}
	return nil
}

func reportGaps(queue <-chan Packet, delta time.Duration) {
	const row = "%4d | %s | %s | %6d | %6d | %8d | %s"

	var (
		count   uint64
		missing uint64
		size    uint64
		elapsed time.Duration
	)

	gs := make(map[int]Packet)
	for curr := range queue {
		count++
		size += uint64(curr.Len())

		id, _ := curr.Id()
		g := curr.Diff(gs[id])
		if g != nil {
			missing += uint64(g.Missing())
			elapsed += g.Duration()

			p := g.Starts.Add(delta).Format(TimeFormat)
			c := g.Ends.Add(delta).Format(TimeFormat)
			log.Printf(row, g.Id, p, c, g.Last, g.First, g.Missing(), g.Duration())
		}
		gs[id] = curr
	}
	log.Printf("%d packets found (%dMB) - missing: %d (time: %s)", count, size>>20, missing, elapsed)
}

func reportCounts(queue <-chan Packet) {
	gs := make(map[int]*Coze)
	ps := make(map[int]Packet)
	for p := range queue {
		id, _ := p.Id()
		c, ok := gs[id]
		if !ok {
			c = &Coze{}
		}
		c.Count++
		c.Size += uint64(p.Len())
		if g := p.Diff(ps[id]); g != nil {
			c.Missing += uint64(g.Missing())
		}
		if p, ok := p.(*VMUPacket); ok && p.HRH.Error != 0 {
			c.Error++
		}
		gs[id], ps[id] = c, p
	}
	var z Coze
	for c, s := range gs {
		z.Update(s)
		log.Printf("%4d | %8d | %8d | %8dMB | %8d", c, s.Count, s.Missing, s.Size>>20, s.Error)
	}
	log.Printf("%4d | %8d | %8d | %8dMB | %8d", 0, z.Count, z.Missing, z.Size>>20, z.Error)
}
