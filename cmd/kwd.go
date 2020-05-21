package main

import (
	"fmt"

	"github.com/bunji2/vulns"
)

// KwData は脆弱性レポートのキーワードでインデクスしたデータを格納する構造体型
type KwData struct {
	Keywords []string       `json:"keywords"` // キーワードのリスト
	Tab      [][]string     `json:"tab"`      // キーワードＩＤに紐づく脆弱性レポートＩＤの対応を格納するテーブル
	kwIDs    map[string]int // キーワードからキーワードＩＤへのマップ
}

// LoadKwData はファイルに保存された KwData を読みだす関数。
func LoadKwData(filePath string) (r *KwData, err error) {
	var t KwData
	err = vulns.LoadJSON(filePath, &t)
	if err != nil {
		return
	}
	r = &t
	r.kwIDs = map[string]int{}
	for kwID, kw := range r.Keywords {
		r.kwIDs[kw] = kwID
	}
	return
}

// Save は KwData をファイルに保存する関数。
func (kwd *KwData) Save(filePath string) (err error) {
	err = vulns.SaveJSON(filePath, kwd)
	return
}

// getKwID はキーワードのＩＤを取得する関数
func (kwd *KwData) getKwID(kw string) (r int) {
	_, ok := kwd.kwIDs[kw]
	if !ok { // kwIDs にまだ格納されてない時
		kwd.kwIDs[kw] = len(kwd.Keywords)
		kwd.Keywords = append(kwd.Keywords, kw)
	}
	r = kwd.kwIDs[kw]
	return
}

// add はキーワードＩＤとレポートＩＤの対応をテーブルに格納する関数
func (kwd *KwData) add(kwID int, reportID string) {
	for kwID >= len(kwd.Tab) {
		// kwID が kwTab のサイズ以上のときは kwTab に空配列をアペンドする。
		kwd.Tab = append(kwd.Tab, []string{})
	}
	reportIDs := kwd.Tab[kwID]
	kwd.Tab[kwID] = append(reportIDs, reportID)
}

// Print は kwTab を表示する関数
func (kwd *KwData) Print() {
	//fmt.Println("print", len(kwd.Keywords))
	for kwID, kw := range kwd.Keywords {
		fmt.Println(kwID, kw)
		fmt.Println("\t", kwd.Tab[kwID])
	}
}
