// 脆弱性レポートのダイジェストを作成するコマンド
// Usage: vulns digest id [ id ... ]
//     id --- 脆弱性レポートのID。もしくは CVE-ID

package main

import (
	"fmt"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/digest"
)

const (
	cmdDigestFmt = "id [ id ... ]\n"
)

func processDigest(args []string) (err error) {

	// 引数のチェック
	if len(args) < 1 {
		err = fmt.Errorf("too few arguments")
		return
	}
	ids := args

	// digest パッケージの初期化
	err = digest.InitConfig(confFile)
	if err != nil {
		return
	}

	// 引数で指定されたIDについてダイジェスト化
	for _, id := range ids {
		err = _processDigest(id)
		if err != nil {
			return
		}
	}

	return
}

// _processDigest は指定されたIDの脆弱性レポートのダイジェストを表示する関数
func _processDigest(id string) (err error) {
	// id で指定される脆弱性レポートを取得
	var r vulns.VulnReport
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}

	// 脆弱性レポートのダイジェストの作成
	d := digest.Digest(r)

	// ダイジェストの表示
	fmt.Println("----")
	fmt.Println(d)

	return
}
