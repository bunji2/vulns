package main

import (
	"fmt"
	"os"
)

const (
	confFile = "/opt/vulns/etc/config.json"
	cmdFmt   = "Usage: %s [ fetch YYYY [ csv out.csv | json ] | digest id [ ... ] | report id [ ... ] | help | version ]\n"
)

var helpItems = [][]string{
	[]string{
		"vulns fetch YYYY [ csv out.csv | json ]",
		"YYYY年の脆弱性レポート群を CSV あるいは JSON で取得",
	},
	[]string{
		"vulns digest id [ ... ]",
		"識別番号 id の脆弱性レポートのダイジェストを表示",
	},
	[]string{
		"vulns report id [ ... ]",
		"識別番号 id の脆弱性レポートの表示",
	},
	[]string{
		"vulns help",
		"この HELP の表示",
	},
	[]string{
		"vulns version",
		"バージョンの表示",
	},
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, cmdFmt, os.Args[0])
		return 1
	}

	cmd := os.Args[1]

	var err error
	switch cmd {
	case "fetch":
		err = processFetch(os.Args[2:])
	case "digest":
		err = processDigest(os.Args[2:])
	case "report":
		err = processReport(os.Args[2:])
	case "version":
		err = processVersion()
	case "help":
		err = processHelp()
	default:
		err = fmt.Errorf(`cmd %s is unknown`, cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintf(os.Stderr, cmdFmt, os.Args[0])
		return 2
	}

	return 0
}

func processHelp() error {
	fmt.Fprintf(os.Stderr, "Vulns Help\n")
	for _, helpItem := range helpItems {
		fmt.Fprintf(os.Stderr, " %s\n    %s\n", helpItem[0], helpItem[1])
	}
	return nil
}

func processVersion() error {
	fmt.Printf("Vulns Version:%s\n", VERSION)
	return nil
}
