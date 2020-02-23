package digest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bunji2/vulns"
)

const (
	// defaultPat は主要な脆弱性のテキストのパターン
	defaultVulnPat     = `(における|において|に関する|に)(.*脆弱性)`
	defaultPickupIndex = 2 // (.+脆弱性) の部分のインデックス番号
)

var dataFolder string        // 脆弱性レポートデータの格納されるフォルダ
var cveIDs map[string]string // cveID のリスト

var kwRule TypeKwRule // キーワードルールのリスト

var vulnPatReg *regexp.Regexp // 脆弱性テキストのパターンの正規表現オブジェクト
var pickupIndex int           // 上の正規表現のマッチング結果から抽出すつインデクス番号

// Init はこのパッケージを初期化する関数
func Init(c Config) (err error) {
	// データフォルダの有無をチェック
	if !dirExists(c.DataFolder) {
		err = fmt.Errorf("%s is not directory", c.DataFolder)
		return
	}
	dataFolder = c.DataFolder

	// cveids.json の読み出し
	cveIDsFile := fmt.Sprintf("%s/cveids.json", dataFolder)
	cveIDs = map[string]string{}
	vulns.LoadJSON(cveIDsFile, &cveIDs)
	/*
		cveIDs, err = loadStrMap(cveIDsFile)
		if err != nil {
			return
		}
	*/

	// キーワードルールファイルの読み出し
	kwRuleFilePat := fmt.Sprintf("%s/*.json", c.RuleFolder)
	kwRule = TypeKwRule{}
	kwRuleFiles, _ := filepath.Glob(kwRuleFilePat)
	for _, kwRuleFile := range kwRuleFiles {
		var tmp TypeKwRule
		tmp, err = LoadKwRule(kwRuleFile)
		if err != nil {
			return
		}
		for k, v := range tmp {
			kwRule[k] = v
		}
	}

	// 主要な脆弱性テキストの正規表現オブジェクトを用意
	if c.VulnPat != "" {
		// コンフィグで指定されている場合
		vulnPatReg = regexp.MustCompile(c.VulnPat)
		pickupIndex = c.PickupIndex
	} else {
		// デフォルト
		vulnPatReg = regexp.MustCompile(defaultVulnPat)
		pickupIndex = defaultPickupIndex
	}
	return
}

// Digest は与えられた脆弱性レポートのダイジェストを作成する関数
func Digest(r vulns.VulnReport) (d VulnDigest) {
	mainVuln := ExtractMainVuln(r.Title)
	vulns := kwRule.Extract(r.Title + " " + r.Overview)
	impacts := kwRule.Extract(r.Impact)
	d = VulnDigest{
		ID:       r.ID,
		CPEs:     r.CPEs,
		CVEs:     r.CVEs,
		CVSSs:    r.CVSSs,
		MainVuln: mainVuln,
		Vulns:    vulns,
		Impacts:  impacts,
	}
	return
}

// dirExists は指定されたディレクトリパスが存在するかどうかを検査する関数
func dirExists(dirPath string) bool {
	f, err := os.Stat(dirPath)
	return !os.IsNotExist(err) && f.IsDir()
}

// ExtractMainVuln はメインの脆弱性を抽出する関数
func ExtractMainVuln(text string) (keyword string) {
	//fmt.Println(text)
	matched := vulnPatReg.FindAllStringSubmatch(text, -1)
	if len(matched) > 0 {
		//fmt.Println(matched)
		if len(matched[0]) > pickupIndex {
			keyword = matched[0][pickupIndex]
		}
	}
	keyword = strings.TrimSpace(keyword)
	return
}
