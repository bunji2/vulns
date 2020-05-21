// 脆弱性レポートを操作するコマンド
// 設定ファイル： 実行ファイルと同じフォルダの "config.json"
// 設定ファイルのサンプル：
//{
//	"describe": "脆弱性レポートの操作用設定ファイル",
//	"data_folder": "./data",
//	"rule_folder": "./rules",
//	"vuln_pat": "(における|において|に関する|に)(.*脆弱性)",
//	"pickup_index": 2,
//	"use_gzip": true
//}
//

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	confFileName = "config.json"
	cmdFmt       = "Usage: %s [ fetch YYYY [ csv out.csv | json ] | digest id [ ... ] | report id [ ... ] | help | version ]\n"
)

// helpItems はヘルプ表示用の項目を格納する変数
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
	[]string{
		"vulns index [verbose]",
		"インデックスの作成",
	},
	[]string{
		"vulns html",
		"HTMLの作成",
	},
}

var confFile string

func main() {
	os.Exit(run())
}

func run() int {
	// 引数のチェック
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, cmdFmt, os.Args[0])
		return 1
	}

	// 設定ファイルのパスの特定
	confFile = resolvConfFile()

	var err error

	// 第一引数のコマンド名で分岐
	cmd := os.Args[1]
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
	case "index":
		err = processIndex(os.Args[2:])
	case "html":
		err = processHTML(os.Args[2:])

	// case "Foo"
	// コマンドを追加するときはこの位置に挿入する。

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

// processHelp はヘルプ表示関数
func processHelp() error {
	fmt.Fprintf(os.Stderr, "Vulns Help\n")
	for _, helpItem := range helpItems {
		fmt.Fprintf(os.Stderr, " %s\n    %s\n", helpItem[0], helpItem[1])
	}
	return nil
}

// processVersion はバージョン表示関数
func processVersion() error {
	fmt.Printf("Vulns Version:%s\n", VERSION)
	return nil
}

// resolvConfFile は設定ファイルのパスを特定する関数
func resolvConfFile() string {
	// 実行ファイルのパスを特定
	exe, err := os.Executable()
	if err == nil {
		// 実行ファイルのあるディレクトリ配下の設定ファイルのパス
		return filepath.Dir(exe) + "/" + confFileName
	}

	// つまりカレントディレクトリ配下の設定ファイルのパス
	return confFileName
}
