// 取得した脆弱性レポートデータとキーワードとの対応表を作成する
// Usage: vulns index [verbose]

package main

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/digest"
)

const (
	kwIndexFile = "index.json"
	cmdIndexFmt = "vulns index [verbose]"
)

var kwd *KwData

func processIndex(args []string) (err error) {
	var verbose bool

	// digest パッケージの初期化
	err = digest.InitConfig(confFile)
	if err != nil {
		return
	}

	if len(args) > 0 && args[0] == "verbose" {
		verbose = true
	}
	dataFolder := vulns.GetDataFolder()

	// データフォルダに格納されている脆弱性レポートのＩＤのリストを取得
	var ids []string
	ids, err = getReportIDs(dataFolder)
	//fmt.Println(ids)

	kwd = &KwData{
		Tab:   [][]string{},
		kwIDs: map[string]int{},
	}

	var kws []string
	for _, id := range ids {
		kws, err = getKws(id)
		if err != nil {
			break
		}
		//fmt.Println(kws)
		for _, kw := range kws {
			kwID := kwd.getKwID(kw)
			kwd.add(kwID, id)
		}
	}
	if verbose {
		kwd.Print()
	}
	err = kwd.Save(dataFolder + "/" + kwIndexFile)
	return
}

func getReportIDs(dataFolder string) (ids []string, err error) {
	var files []os.FileInfo
	files, err = ioutil.ReadDir(dataFolder)
	if err != nil {
		return
	}
	for _, file := range files { //debug:limitter [0:20] {
		if !file.IsDir() {
			if strings.HasPrefix(file.Name(), "JVNDB-") { // JVNDB-YYYY-NNNNNN
				ids = append(ids, file.Name()[0:17])
			}
		}
	}
	return
}

// getKws は指定されたIDの脆弱性レポートのキーワードを取得する関数
func getKws(id string) (kws []string, err error) {
	// id で指定される脆弱性レポートを取得
	var r vulns.VulnReport
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}

	// 脆弱性レポートのダイジェストの作成
	d := digest.Digest(r)

	// ダイジェストのキーワード群を取得
	kws = append(kws, d.MainVuln)
	for _, k := range d.Vulns {
		kws = append(kws, k)
	}
	for _, k := range d.Impacts {
		kws = append(kws, k)
	}

	// ダイジェストの表示
	//fmt.Println("----")
	//fmt.Println(d)

	return
}
