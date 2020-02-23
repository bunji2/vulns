package digest

import (
	"encoding/json"
	"io/ioutil"
)

// loadStrArrayMap は JSON 形式で保存された文字列マップを読み出す関数
func loadStrArrayMap(filePath string) (r map[string][]string, err error) {
	r = map[string][]string{}

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
