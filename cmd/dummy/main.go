package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/busoc/meex"
	"github.com/busoc/meex/cmd/internal/multireader"
	"github.com/midbel/xxh"
)

func main() {
	mem := flag.String("m", "", "memory profile")
	flag.Parse()

	var files []string
	if flag.NArg() == 0 {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			files = append(files, s.Text())
		}
	} else {
		files = flag.Args()
	}

	dumpPackets(files)
	if *mem != "" {
		w, err := os.Create(*mem)
		if err != nil {
			return
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(w); err != nil {
			log.Println("fail to write heap profile ", err)
		}
		w.Close()
	}
}

func dumpPackets(files []string) error {
	if len(files) == 0 {
		return nil
	}
	mr, err := multireader.New(files, true)
	if err != nil {
		log.Fatalln(err)
	}
	rt := meex.NewReader(mr, meex.Empty())

	x := xxh.New64(0)
	for i := 1; ; i++ {
		p, err := rt.Next()
		if err != nil {
			break
		}
		ts := p.Timestamp().Format(time.RFC3339)
		x.Write(p.Bytes())
		fmt.Fprintf(os.Stdout, "%d | %d | %8d | %s | %016x\n", i, p.Sequence(), p.Len(), ts, x.Sum64())

		p = nil
	}
	return nil
}
