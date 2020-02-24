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

// InitConfig は設定をファイルから読み出してパッケージを初期化する関数 LoadConfig してから Init する。
func InitConfig(filePath string) (err error) {
	var c Config
	c, err = LoadConfig(filePath)
	if err != nil {
		return
	}
	err = Init(c)
	return
}
