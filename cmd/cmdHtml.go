// 脆弱性レポートデータからHTMLを作成する
// Usage: vulns html outdir

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

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

	titles := map[string]string{}
	err = makeReportHTMLs(outDir, ids, titles)
	if err != nil {
		return
	}

	err = makekwDataHTMLs(outDir, titles)

	if verbose {
		kwd.Print()
	}
	return
}

// makekwDataHTMLs は脆弱性レポートのキーワードデータ群からＨＴＭＬを作成する関数
func makekwDataHTMLs(outDir string, titles map[string]string) (err error) {
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
	fmt.Fprintf(b, `<p><a href="index.html">[All reports]</a> </p><hr>`)
	for kwID, kw := range kwd.Keywords {
		fmt.Fprintf(b, `<p><a href="kw%d.html">%s</a></p> 
`, kwID, kw)
		filePath := fmt.Sprintf("%s/kw%d.html", outDir, kwID)
		err = makekwDataHTML(filePath, kw, kwd.Tab[kwID], titles)
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
func makekwDataHTML(filePath, kw string, ids []string, titles map[string]string) (err error) {
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
	fmt.Fprintf(b, `<p><a href="index.html">[All reports]</a> <a href="keywords.html">[All keywords]</a> </p><hr>`)
	fmt.Fprintf(b, "<p><b>[%s]</b></p>\n", kw)
	for i := len(ids) - 1; i >= 0; i-- {
		id := ids[i]
		fmt.Fprintf(b, `<p><a href="%s.html">%s : %s</a></p> 
`, id, id, titles[id])
	}
	fmt.Fprintln(b, `</body>
</html>`)
	w.Write(b.Bytes())
	return
}

// makeReportHTMLs は脆弱性レポート群のＨＴＭＬを作成する関数
func makeReportHTMLs(outDir string, ids []string, titles map[string]string) (err error) {
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
	fmt.Fprintf(b, `<p><a href="keywords.html">[All keywords]</a> </p><hr>`)
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
		titles[id] = r.Title
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
	fmt.Fprintf(b, `<p><a href="index.html">[All reports]</a> <a href="keywords.html">[All keywords]</a> </p><hr>`)
	fmt.Fprintf(b, "<p>")
	kws := map[string]bool{}
	for _, kw := range d.Vulns {
		kws[kw] = true
	}
	for _, kw := range d.Impacts {
		kws[kw] = true
	}
	fmt.Fprintf(b, `<a href="kw%d.html">[%s]</a> `, kwd.kwIDs[d.MainVuln], d.MainVuln)
	for kw := range kws {
		fmt.Fprintf(b, `<a href="kw%d.html">[%s]</a> `, kwd.kwIDs[kw], kw)
	}
	fmt.Fprintln(b, "</p>")

	yyyy := r.ID[6:10] // JVNDB-YYYY-NNNNNN
	jvnURL := fmt.Sprintf("https://jvndb.jvn.jp/ja/contents/%s/%s.html", yyyy, r.ID)
	fmt.Fprintf(b, "<p><b><a href=\"%s\" target=\"_NEWWINDOW\">%s</a></b></p>\n", jvnURL, r.ID)
	fmt.Fprintf(b, "<p>Title:%s</p>\n", r.Title)
	fmt.Fprintf(b, "<p>Overview: %s</p>\n", r.Overview)
	fmt.Fprintf(b, "<p>Impact: %s</p>\n<p>", r.Impact)
	fmt.Fprintf(b, "<p>CPE:<br>%s</p>\n", strings.Join(r.CPEs, "<br>\n"))
	fmt.Fprintf(b, "<p>CVSS:<br>%s</p>\n", strings.Join(r.CVSSs, "<br>\n"))
	fmt.Fprintf(b, "<p>CVE:<br>%s</p>\n", strings.Join(r.CVEs, "<br>\n"))
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
