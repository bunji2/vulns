// 脆弱性レポートを表示するコマンド
// Usage: vulns report id [ id ... ]
//     id --- 脆弱性レポートのID。もしくは CVE-ID

package main

import (
	"fmt"

	"github.com/bunji2/vulns"
)

const (
	cmdReportFmt = "id [ id ... ]\n"
)

func processReport(args []string) (err error) {
	// 引数のチェック
	if len(args) < 1 {
		err = fmt.Errorf("too few arguments")
		return
	}
	ids := args

	// vulns パッケージの初期化
	err = vulns.InitConfig(confFile)
	if err != nil {
		return
	}

	// 各 ID の脆弱性レポートを表示
	for _, id := range ids {
		err = _processReport(id)
		if err != nil {
			return
		}
	}

	return
}

// _processReport は脆弱性レポートを表示する関数
func _processReport(id string) (err error) {
	// 脆弱性レポートの取得
	var r vulns.VulnReport
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}

	// 脆弱性レポートの表示
	fmt.Println("----")
	fmt.Println(r)
	return
}
