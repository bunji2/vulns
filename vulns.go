package vulns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

var useGzip bool             // 脆弱性レポートデータを Gzip 圧縮するかどうかのフラグ
var dataFolder string        // 脆弱性レポートデータの格納されるフォルダ
var cveIDs map[string]string // cveID のリスト（CVEID -> 脆弱性レポートのID）

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

// resolveVulnReportPath は与えられた ID の脆弱性レポートのファイルパスを返す関数。
// 引数 id は脆弱性レポートの ID そのものか、CVEID のいずれか。
func resolveVulnReportPath(id string) (filePath string, err error) {
	if dataFolder == "" {
		// [Memo] データフォルダが初期化されないのは Init 関数を読んでない可能性
		err = fmt.Errorf("dataFolder is empty")
		return
	}

	// 処理対象となる脆弱性レポートの ID を格納する変数
	targetID := id
	
	// [TODO] id のパターンチェックを行うべき。
	// JVNDB : JVNDB-YYYY-NNNNNN
	// CVE   : CVE-YYYY-NNNN
	// 以下の実装ではプレフィックスのみチェックしている。
	
	// "CVE-" のパターンの ID の場合
	if strings.HasPrefix(targetID, "CVE-") {
		// "CVE-" で始まるIDの場合は、cveIDsのマップで既知の CVEID かどうかを
		// 確認し、既知の場合は targetID に対応する脆弱性レポートの ID に変換する。
		cve, ok := cveIDs[targetID]
		if !ok {
			err = fmt.Errorf("%s is unknown id", targetID)
			return
		}
		targetID = cve
	}
	
	// もし他の ID のパターンがあればこの位置に対応する処理を挿入する。
	
	// あとは "JVNDB-" のパターンの ID のみ
	if !strings.HasPrefix(targetID, "JVNDB-") {
		err = fmt.Errorf("%s is unknown id", targetID)
		return
	}
	
	// データフォルダと脆弱性レポートの ID から参照するファイルを特定
	filePath = fmt.Sprintf("%s/%s.json", dataFolder, targetID)
	
	// useGzip フラグが有効な場合は拡張子に ".gz" を追加する。
	if useGzip {
		filePath = filePath + ".gz"
	}
	return
}

// loadStrMap は JSON 形式で保存された文字列マップ(map[string]string)を読み出す関数
func loadStrMap(filePath string) (r map[string]string, err error) {
	// [TODO] 主に cveids.json の読み出しに使う予定だが、
	//        汎用的な関数なので utils.go に移動するべきか後で検討する。
	
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
