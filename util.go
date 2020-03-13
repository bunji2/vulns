package vulns

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
)

// LoadJSON はファイルに保存された JSON オブジェクトを読み出す関数
func LoadJSON(filePath string, out interface{}) (err error) {
	// バイト列読み出し
	var bytes []byte
	bytes, err = ioutil.ReadFile(filePath)
	if err != nil {
		return
	}

	// json 形式のデコード
	err = json.Unmarshal(bytes, out)
	return
}

// LoadGzipedJSON は Gzip ファイルに保存された JSON オブジェクトを読み出す関数
func LoadGzipedJSON(filePath string, out interface{}) (err error) {
	var f *os.File
	f, err = os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	var r *gzip.Reader
	r, err = gzip.NewReader(f)
	if err != nil {
		return
	}

	// バイト列読み出し
	var bytes []byte
	bytes, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	// json 形式のデコード
	err = json.Unmarshal(bytes, out)
	return
}

// SaveJSON は脆弱性レポートを JSON 形式でファイル保存する関数
func SaveJSON(outFile string, v interface{}) (err error) {
	var w *os.File
	w, err = os.Create(outFile)
	if err != nil {
		return
	}
	defer w.Close()
	var b []byte
	b, err = json.Marshal(v)
	if err != nil {
		return
	}
	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	if err != nil {
		return
	}
	_, err = out.WriteTo(w)
	return
}

// SaveGzipedJSON は脆弱性レポートを JSON 形式でファイル保存する関数
func SaveGzipedJSON(outFile string, v interface{}) (err error) {
	var f *os.File
	f, err = os.Create(outFile)
	if err != nil {
		return
	}
	defer f.Close()

	w := gzip.NewWriter(f)
	defer w.Close()

	var b []byte
	b, err = json.Marshal(v)
	if err != nil {
		return
	}
	var out bytes.Buffer
	err = json.Indent(&out, b, "", "  ")
	if err != nil {
		return
	}
	_, err = out.WriteTo(w)
	return
}

// SaveCSVs は脆弱性レポートを CSV 形式ファイルに保存する関数
func SaveCSVs(csvFilePath string, records []VulnReport) (err error) {
	var w *os.File
	w, err = os.Create(csvFilePath)
	if err != nil {
		return
	}
	defer w.Close()
	cw := csv.NewWriter(w) // utf8
	err = cw.Write([]string{
		"ID",
		"Title",
		"Overview",
		"Impact",
		"CVEs",
		"CVSSs",
	})

	for _, record := range records {
		cols := []string{
			record.ID,
			record.Title,
			record.Overview,
			record.Impact,
			strings.Join(record.CVEs, "|"),
			strings.Join(record.CVSSs, "|"),
		}
		err = cw.Write(cols)
		if err != nil {
			break
		}
	}
	cw.Flush()
	return
}

// SaveJSONs : JSON 形式ファイルにデータを保存する
func SaveJSONs(records []VulnReport) (err error) {
	//cveIDsFile := fileOp.CveIDsFilePath()
	for _, record := range records {
		err = fileOp.SaveVulnReport(record)
		if err != nil {
			break
		}
		for _, cveID := range record.CVEs {
			cveIDs[cveID] = record.ID
		}
	}
	if err == nil {
		err = fileOp.SaveCveIDs(cveIDs)
		//err = SaveJSON(cveIDsFile, cveIDs)
	}
	return
}

// fileExists は指定されたファイルパスが存在するかどうかを検査する関数
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// dirExists は指定されたディレクトリパスが存在するかどうかを検査する関数
func dirExists(dirPath string) bool {
	f, err := os.Stat(dirPath)
	return !os.IsNotExist(err) && f.IsDir()
}

/*
// loadStrMap は JSON 形式で保存された文字列マップ(map[string]string)を読み出す関数
func loadStrMap(filePath string) (r map[string]string, err error) {

	r = map[string]string{}

	// バイト列読み出し
	var bytes []byte
	bytes, err = ioutil.ReadFile(filePath)
	if err != nil {
		return
	}

	// json 形式のデコード
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		return
	}
	return
}
*/
