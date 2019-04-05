package main

import (
	"io"
	"log"
	"os"

	"github.com/busoc/meex"
	"github.com/busoc/pdh"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
)

var commands = []*cli.Command{
	{
		Usage: "list [-i] [-g] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff [-i] [-g] <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count [-g] <file...>",
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
  defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("prx", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}


func runList(cmd *cli.Command, args []string) error {
  csv := cmd.Flag.Bool("c", false, "csv format")
  if err := cmd.Flag.Parse(args); err!= nil {
    return err
  }
  d, err := Decode(cmd.Flag.Args())
	if err != nil {
		return err
	}
  var options []func(*linewriter.Writer)
	if *csv {
		options = append(options, linewriter.AsCSV(false))
	} else {
		options = []func(*linewriter.Writer) {
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	line := linewriter.NewWriter(1024, options...)

  for {
    p, err := d.Decode(false)
    if err != nil {
      if err == io.EOF {
        break
      }
      return err
    }
    dumpPacket(line, p)
  }
  return nil
}

func runCount(cmd *cli.Command, args []string) error {
  return cmd.Flag.Parse(args)
}

func runDiff(cmd *cli.Command, args []string) error {
  return cmd.Flag.Parse(args)
}

func Decode(files []string) (*pdh.Decoder, error) {
	mr, err := meex.Browse(files, true)
	if err != nil {
		return nil, err
	}
	return pdh.NewDecoder(meex.NewReader(mr)), nil
}

func dumpPacket(line *linewriter.Writer, p pdh.Packet) {
  defer line.Reset()
  
  line.AppendTime(p.Timestamp(), meex.TimeFormat, linewriter.AlignCenter)
  line.AppendString(p.State.String(), 8, linewriter.AlignRight)
  line.AppendBytes(p.Code[:], 0, linewriter.Hex)
  line.AppendUint(uint64(p.Orbit), 8, linewriter.Hex|linewriter.WithZero)
  line.AppendString(p.Type.String(), 12, linewriter.AlignRight)
  line.AppendUint(uint64(p.Len), 8, linewriter.AlignRight)

  os.Stdout.Write(append(line.Bytes(), '\n'))
}
