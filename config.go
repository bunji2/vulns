package vulns

// Config はパッケージの設定情報の型
type Config struct {
	DataFolder string `json:"data_folder"`
	UseGzip    bool   `json:"use_gzip"`
}

// LoadConfig は設定をファイルから読み出す関数
func LoadConfig(filePath string) (c Config, err error) {
	c = Config{}
	err = LoadJSON(filePath, &c)
	//fmt.Println("# data folder =", c.DataFolder)
	//fmt.Println("# use zip =", c.UseGzip)
	return
}
