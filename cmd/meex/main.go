package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/midbel/cli"
)

var commands = []*cli.Command{
	sortCommand,
	mixCommand,
	scanCommand,
	extractCommand,
	listCommand,
	takeCommand,
	sumCommand,
	indexCommand,
	dispatchCommand,
	shuffleCommand,
	joinCommand,
	diffCommand,
	countCommand,
	errCommand,
	storeCommand,
}

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

type Kind struct {
	Decod Decoder
	Sort  SortFunc
}

func SortHRDIndex(ix []*Index) []*Index {
	sort.Slice(ix, func(i, j int) bool {
		if ix[i].Timestamp.Equal(ix[j].Timestamp) {
			if ix[i].Id != ix[j].Id {
				return ix[i].Size < ix[j].Size
			} else {
				return ix[i].Sequence < ix[j].Sequence
			}
		}
		return ix[i].Timestamp.Before(ix[j].Timestamp)
	})
	return ix
}

func SortTMIndex(ix []*Index) []*Index {
	sort.Slice(ix, func(i, j int) bool {
		if ix[i].Timestamp.Equal(ix[j].Timestamp) {
			return ix[i].Sequence < ix[j].Sequence
		}
		return ix[i].Timestamp.Before(ix[j].Timestamp)
	})
	return ix
}

func (k *Kind) Set(v string) error {
	switch strings.ToLower(v) {
	default:
		return fmt.Errorf("unrecognized packet decoder type")
	case "":
		return fmt.Errorf("no packet type provided")
	case "pd", "pp", "pdh":
		k.Decod = DecodePD()
	case "tm", "pth", "pt":
		k.Decod = DecodeTM()
		k.Sort = SortTMIndex
	case "vmu":
		k.Decod = DecodeVMU()
		k.Sort = SortHRDIndex
	case "hrd":
		k.Decod = DecodeHRD()
	}
	return nil
}

func (k *Kind) String() string {
	return "packet decoder type"
}

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	cli.Version = "0.2.4"
	cli.BuildTime = "2019-09-13 11:25:00"
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	if err := cli.Run(commands, cli.Usage("meex", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}
