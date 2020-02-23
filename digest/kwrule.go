package digest

import "strings"

// TypeKwRule はキーワードルールの型。
type TypeKwRule map[string][]string

// LoadKwRule はファイルに保存されたキーワードルールを読み出す関数
func LoadKwRule(filePath string) (TypeKwRule, error) {
	r, e := loadStrArrayMap(filePath)
	return TypeKwRule(r), e
}

// Extract は与えられたテキストに含まれるキーワードを
// キーワードルールに基づいて抽出する関数
func (r TypeKwRule) Extract(text string) (keywords []string) {
	keywords = []string{}
	for title, patterns := range r {
		for _, pattern := range patterns {
			if strings.Contains(text, pattern) {
				keywords = append(keywords, title)
				break
			}
		}
	}
	return
}
