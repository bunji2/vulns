// 脆弱性レポートデータからHTMLを作成する
// Usage: vulns html outdir

package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/digest"
)

const (
	kwDataHTML = "keywords.html"
	cmdHTMLFmt = "outdir [verbose]"
)

func processHTML(args []string) (err error) {
	// 引数のチェック
	if len(args) < 1 {
		err = fmt.Errorf("too few arguments")
		return
	}
	outDir := args[0]

	var verbose bool
	if len(args) > 1 && args[1] == "verbose" {
		verbose = true
	}

	// digest パッケージの初期化
	err = digest.InitConfig(confFile)
	if err != nil {
		return
	}

	dataFolder := vulns.GetDataFolder()

	kwd, err = LoadKwData(dataFolder + "/" + kwIndexFile)
	if err != nil {
		return
	}

	// データフォルダに格納されている脆弱性レポートのＩＤのリストを取得
	var ids []string
	ids, err = getReportIDs(dataFolder)
	if err != nil {
		return
	}

	err = makeReportHTMLs(outDir, ids)
	if err != nil {
		return
	}

	err = makekwDataHTMLs(outDir)

	if verbose {
		kwd.Print()
	}
	return
}

// makekwDataHTMLs は脆弱性レポートのキーワードデータ群からＨＴＭＬを作成する関数
func makekwDataHTMLs(outDir string) (err error) {
	var w *os.File
	w, err = os.Create(outDir + "/" + kwDataHTML)
	if err != nil {
		return
	}
	defer w.Close()
	b := bytes.NewBufferString("")
	fmt.Fprintf(b, `<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>keywords</title>
<body>`)
	for kwID, kw := range kwd.Keywords {
		fmt.Fprintf(b, `<p><a href="kw%d.html">%s</a></p> 
`, kwID, kw)
		filePath := fmt.Sprintf("%s/kw%d.html", outDir, kwID)
		err = makekwDataHTML(filePath, kw, kwd.Tab[kwID])
		if err != nil {
			break
		}
	}
	fmt.Fprintln(b, `</body>
</html>`)
	w.Write(b.Bytes())
	return
}

// makekwDataHTML は脆弱性レポートのキーワードからＨＴＭＬを作成する関数
func makekwDataHTML(filePath, kw string, ids []string) (err error) {
	var w *os.File
	w, err = os.Create(filePath)
	if err != nil {
		return
	}
	defer w.Close()
	b := bytes.NewBufferString("")
	fmt.Fprintf(b, `<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>%s</title>
<body>`, kw)
	fmt.Fprintf(b, "<p><b>[%s]</b></p>\n", kw)
	for _, id := range ids {
		fmt.Fprintf(b, `<p><a href="%s.html">%s</a></p> 
`, id, id)
	}
	fmt.Fprintln(b, `</body>
</html>`)
	w.Write(b.Bytes())
	return
}

// makeReportHTMLs は脆弱性レポート群のＨＴＭＬを作成する関数
func makeReportHTMLs(outDir string, ids []string) (err error) {
	var w *os.File
	w, err = os.Create(outDir + "/" + "index.html")
	if err != nil {
		return
	}
	defer w.Close()

	b := bytes.NewBufferString("")
	fmt.Fprintf(b, `<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>脆弱性レポート</title>
<body>`)
	fmt.Fprintf(b, `<p><a href="keywords.html">keywords</a></p>`)
	var r vulns.VulnReport
	for i := len(ids) - 1; i >= 0; i-- {
		id := ids[i]
		filePath := fmt.Sprintf("%s/%s.html", outDir, id)
		r, err = makeReportHTML(filePath, id)
		if err != nil {
			break
		}
		fmt.Fprintf(b, `<p><a href="%s.html">%s : %s</a></p>
`, id, id, r.Title)
	}
	fmt.Fprintln(b, `</body>
</html>`)
	w.Write(b.Bytes())
	return
}

// makeReportHTML は脆弱性レポートのＨＴＭＬを作成する関数
func makeReportHTML(filePath, id string) (r vulns.VulnReport, err error) {
	var w *os.File
	w, err = os.Create(filePath)
	if err != nil {
		return
	}
	defer w.Close()

	// id で指定される脆弱性レポートを取得
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}

	// 脆弱性レポートのダイジェストの作成
	d := digest.Digest(r)

	b := bytes.NewBufferString("")
	fmt.Fprintf(b, `<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>%s : %s</title>
<body>`, r.ID, r.Title)
	fmt.Fprintf(b, "<p><b>%s</b></p>\n", r.ID)
	fmt.Fprintf(b, "<p>Title: %s</p>\n", r.Title)
	fmt.Fprintf(b, "<p>Overview: %s</p>\n", r.Overview)
	fmt.Fprintf(b, "<p>Impact: %s</p>\n<p>", r.Impact)
	for _, kw := range d.Vulns {
		fmt.Fprintf(b, `<a href="kw%d.html">[%s]</a> `, kwd.kwIDs[kw], kw)
	}
	for _, kw := range d.Impacts {
		fmt.Fprintf(b, `<a href="kw%d.html">[%s]</a> `, kwd.kwIDs[kw], kw)
	}
	fmt.Fprintln(b, `</body>
</html>`)
	w.Write(b.Bytes())
	return
}

/*
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
*/
