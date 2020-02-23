package vulns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

var useGzip bool
var dataFolder string        // 脆弱性レポートデータの格納されるフォルダ
var cveIDs map[string]string // cveID のリスト

// Init はパッケージを初期化する関数
func Init(c Config) (err error) {
	dataFolder = c.DataFolder
	useGzip = c.UseGzip

	// cveids.json の読み出し
	cveIDsFile := fmt.Sprintf("%s/cveids.json", dataFolder)
	cveIDs = map[string]string{}
	LoadJSON(cveIDsFile, &cveIDs)
	//cveIDs, _ = loadStrMap(cveIDsFile)
	return
}

// LoadVulnReportFromID は ID で指定された脆弱性レポートをファイルから読み出す関数
func LoadVulnReportFromID(id string) (r VulnReport, err error) {
	var filePath string
	filePath, err = resolveVulnReportPath(id)
	if err != nil {
		return
	}
	//fmt.Println("filePath =", filePath)
	r, err = LoadVulnReport(filePath)
	return
}

// resolveVulnReportPath は与えられた ID の脆弱性レポートのファイルパスを返す関数
func resolveVulnReportPath(id string) (filePath string, err error) {
	if dataFolder == "" {
		err = fmt.Errorf("dataFolder is empty")
		return
	}

	targetID := id
	// [TODO] id のパターンチェック。
	// JVNDB : JVNDB-YYYY-NNNNNN
	// CVE   : CVE-YYYY-NNNN
	if strings.HasPrefix(targetID, "CVE-") {
		cve, ok := cveIDs[targetID]
		if !ok {
			err = fmt.Errorf("%s is unknown id", targetID)
			return
		}
		targetID = cve
	}
	if !strings.HasPrefix(targetID, "JVNDB-") {
		err = fmt.Errorf("%s is unknown id", targetID)
		return
	}
	filePath = fmt.Sprintf("%s/%s.json", dataFolder, targetID)
	if useGzip {
		filePath = filePath + ".gz"
	}
	return
}

// loadStrMap は JSON 形式で保存された文字列マップを読み出す関数
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
