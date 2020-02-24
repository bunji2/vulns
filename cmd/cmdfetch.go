// 西暦年ごとの脆弱性レポートデータをダウンロードし、ファイルに保存するプログラム
// Usage: vulns fetch YYYY [ csv outfile.csv | json outdir ]
//    YYYY --- ダウンロード対象となる西暦（半角数字4桁）
//    csv  outfile.csv --- CSV 形式で所定のパスのファイルに出力
//    json outdir      --- JSON 形式で所定のディレクトリに出力

package main

import (
	"fmt"
	"strconv"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/jvn"
)

const (
	cmdFetchFmt = "YYYY [ csv out.csv | json ]"
	subCmdCsv   = "csv"
	subCmdJSON  = "json"
)

func processFetch(args []string) (err error) {
	//fmt.Println("args =", args)
	if len(args) < 2 {
		err = fmt.Errorf("too few arguments")
		return
	}
	yyyy := args[0]
	subCmd := args[1]
	outPath := ""

	if subCmd == subCmdCsv {
		if len(args) < 3 {
			err = fmt.Errorf("too few arguments")
			return
		}
		outPath = args[2]
	}

	var year int
	year, err = strconv.Atoi(yyyy)
	if err != nil {
		return
	}

	if subCmd != subCmdCsv && subCmd != subCmdJSON {
		err = fmt.Errorf(`sub cmd %s should be "csv" or "json"`, subCmd)
		return
	}

	err = jvn.Init()
	if err != nil {
		return
	}

	var data []vulns.VulnReport
	data, err = jvn.Fetch(year)
	if err != nil {
		return
	}
	//fmt.Println(data)
	/*
		for i, record := range data {
			fmt.Println(i, record)
		}
	*/
	var c vulns.Config
	c, err = vulns.LoadConfig(confFile)
	if err != nil {
		return
	}
	err = vulns.Init(c)
	if err != nil {
		return
	}
	//fmt.Println("sub cmd =", subCmd)
	if subCmd == subCmdCsv {
		err = vulns.SaveCSVs(outPath, data)
	} else { // subCmd == subCmdJSON
		err = vulns.SaveJSONs(data)
	}
	return
}
