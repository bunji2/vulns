// 西暦年ごとの脆弱性レポートデータをダウンロードし、ファイルに保存するコマンド
// Usage: vulns fetch YYYY [ csv outfile.csv | json ]
//    YYYY --- ダウンロード対象となる西暦（半角数字4桁）
//    csv  outfile.csv --- CSV 形式で指定のファイルパスに出力
//    json             --- JSON 形式で設定ファイルで指定したフォルダに出力

package main

import (
	"fmt"
	"strconv"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/fetch"
)

const (
	cmdFetchFmt = "YYYY [ csv out.csv | json ]"
	subCmdCsv   = "csv"
	subCmdJSON  = "json"
)

func processFetch(args []string) (err error) {
	// 引数のチェック
	if len(args) < 2 {
		err = fmt.Errorf("too few arguments")
		return
	}

	// 引数のセット
	yyyy := args[0]
	subCmd := args[1]
	outPath := ""

	// サブコマンドのときは outPath をセットする
	if subCmd == subCmdCsv {
		if len(args) < 3 {
			err = fmt.Errorf("too few arguments")
			return
		}
		outPath = args[2]
	}

	// 西暦年の文字列から整数に変換
	var year int
	year, err = strconv.Atoi(yyyy)
	if err != nil {
		return
	}

	// "csv" と "json" 以外のサブコマンド時にはエラー
	if subCmd != subCmdCsv && subCmd != subCmdJSON {
		err = fmt.Errorf(`sub cmd %s should be "csv" or "json"`, subCmd)
		return
	}

	// fetch パッケージの初期化
	err = fetch.InitConfig(confFile)
	if err != nil {
		return
	}

	// year 年の脆弱性レポートのデータを取得
	var data []vulns.VulnReport
	data, err = fetch.Fetch(year)
	if err != nil {
		return
	}

	if subCmd == subCmdCsv {
		// csv 形式でファイルに保存
		err = vulns.SaveCSVs(outPath, data)
	} else { // subCmd == subCmdJSON
		// json 形式でファイルに保存
		err = vulns.SaveJSONs(data)
	}
	return
}
