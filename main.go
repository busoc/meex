package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/midbel/cli"
)

var commands = []*cli.Command{
	// {
	// 	Usage: "distrib",
	// 	Alias: []string{"server"},
	// 	Short: "allow access to archives via a REST API",
	// },
	// {
	// 	Usage: "dump",
	// 	Short: "dumps parameters from packets into RT file(s)",
	// },
	sortCommand,
	mixCommand,
	scanCommand,
	extractCommand,
	listCommand,
	mergeCommand,
	takeCommand,
	sumCommand,
	statsCommand,
	indexCommand,
	dispatchCommand,
	shuffleCommand,
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
	case "tm", "pth", "pt":
		k.Decod = DecodeTM()
		k.Sort = SortTMIndex
	case "hrd", "hr", "hrdl":
		k.Decod = DecodeVMU()
		k.Sort = SortHRDIndex
	}
	return nil
}

func (k *Kind) String() string {
	return "packet decoder type"
}

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	cli.Version = "0.1.0"
	cli.BuildTime = "2018-08-16 07:10:00"
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		fs := map[string]interface{}{
			"join": strings.Join,
		}
		sort.Slice(data.Commands, func(i, j int) bool { return data.Commands[i].String() < data.Commands[j].String() })
		t := template.Must(template.New("help").Funcs(fs).Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}
