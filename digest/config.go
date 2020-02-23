package digest

import (
	"github.com/bunji2/vulns"
)

// Config はこのパッケージの設定を格納するデータの型
type Config struct {
	Describe    string `json:"describe"`
	DataFolder  string `json:"data_folder"`
	RuleFolder  string `json:"rule_folder"`
	VulnPat     string `json:"vuln_pat"`
	PickupIndex int    `json:"pickup_index"`
	UseGzip     bool   `json:"use_gzip"`
}

// LoadConfig は設定をファイルから読み出す関数
func LoadConfig(filePath string) (c Config, err error) {
	c = Config{}

	err = vulns.LoadJSON(filePath, &c)
	//fmt.Println("data folder =", c.DataFolder, "use zip =", c.UseGzip)
	return
}
