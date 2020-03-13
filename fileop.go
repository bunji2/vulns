package vulns

import (
	"fmt"
	"strings"
)

// FileOp は脆弱性レポート関連のファイル操作オブジェクトの型
// ファイル操作全般をこのオブジェクトで束ねておく。
// 自信はないけどこの設計は "Strategy" デザインパターンだと思う。
type FileOp struct {
	useGzip    bool   // gzip 圧縮するかどうか
	dataFolder string // データフォルダのパス
}

// NewFileOp は新しいファイル操作オブジェクトを生成する関数
func NewFileOp(useGzip bool, dataFolder string) FileOp {
	return FileOp{useGzip: useGzip, dataFolder: dataFolder}
}

// FilePath は脆弱性レポートの ID からファイルパスを作成する関数
func (fo FileOp) FilePath(id string) string {
	// データフォルダと脆弱性レポートの ID から参照するファイルを特定
	filePath := fmt.Sprintf("%s/%s.json", fo.dataFolder, id)

	// useGzip フラグが有効な場合は拡張子に ".gz" を追加する。
	if fo.useGzip {
		filePath = filePath + ".gz"
	}
	return filePath
}

// SaveVulnReport は脆弱性レポートを JSON 形式でファイル保存する関数
func (fo FileOp) SaveVulnReport(v VulnReport) (err error) {
	outFile := fo.FilePath(v.ID)
	//fmt.Println(outFile)
	if fo.useGzip {
		err = SaveGzipedJSON(outFile, v)
	} else {
		err = SaveJSON(outFile, v)
	}
	return
}

// LoadVulnReport は JSON 形式で保存されている脆弱性レポートを読み出す関数。
// 引数 id は脆弱性レポートを特定する識別子として、CVEID も許容する。
func (fo FileOp) LoadVulnReport(id string) (r VulnReport, err error) {
	// 脆弱性レポートのIDの特定
	id, err = fo.resolveVulnReportID(id)
	if err != nil {
		return
	}

	// 脆弱性レポートのファイルパスの特定
	filePath := fo.FilePath(id)

	// 脆弱性レポートデータの初期化
	r = VulnReport{}

	// gzip 圧縮のフラグで分岐
	if fo.useGzip {
		err = LoadGzipedJSON(filePath, &r)
	} else {
		err = LoadJSON(filePath, &r)
	}
	return
}

// CveIDsFilePath は cveids.json のファイルパスを作成する関数
func (fo FileOp) CveIDsFilePath() string {
	return fmt.Sprintf("%s/cveids.json", fo.dataFolder)
}

// LoadCveIDs は cveids.json を読み出す関数
func (fo FileOp) LoadCveIDs(cveIDs *map[string]string) (err error) {
	cveIDsFile := fo.CveIDsFilePath()
	err = LoadJSON(cveIDsFile, cveIDs)
	return
}

// SaveCveIDs は cveids.json を保存する関数
func (fo FileOp) SaveCveIDs(cveIDs map[string]string) (err error) {
	cveIDsFile := fo.CveIDsFilePath()
	err = SaveJSON(cveIDsFile, cveIDs)
	return
}

// resolveVulnReportID は与えられた ID の脆弱性レポートのファイルパスを返す関数。
// 引数 id は脆弱性レポートの ID そのものか、CVEID のいずれか。
func (fo FileOp) resolveVulnReportID(id string) (targetID string, err error) {

	// 処理対象となる脆弱性レポートの ID を格納する変数
	targetID = id

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

	return
}
