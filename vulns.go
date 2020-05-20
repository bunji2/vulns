package vulns

var fileOp FileOp            // ファイル操作オブジェクト
var cveIDs map[string]string // cveID のリスト（CVEID -> 脆弱性レポートのID）

// Init はパッケージを初期化する関数
func Init(c Config) (err error) {

	// ファイル操作オブジェクトの作成
	fileOp = FileOp{dataFolder: c.DataFolder, useGzip: c.UseGzip}

	// cveids.json の読み出し
	cveIDs = map[string]string{}
	err = fileOp.LoadCveIDs(&cveIDs)

	// cveids.json が存在しない場合もあるので、読み出しに失敗しようがしまいが常に成功とする。
	err = nil

	return
}

// LoadVulnReportFromID はファイルに保存された脆弱性レポートを読み出す関数。
// 引数 id は脆弱性レポートを特定する ID だが、CVEID も許容する。
func LoadVulnReportFromID(id string) (VulnReport, error) {
	return fileOp.LoadVulnReport(id)
}

// GetDataFolder はパッケージが使用しているデータフォルダのパスを返す関数。
func GetDataFolder() string {
	return fileOp.dataFolder
}
