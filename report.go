// 脆弱性レポートデータの型に関するコード

package vulns

import (
	"fmt"
	"strings"
)

// VulnReport は脆弱性レポートのデータの型
type VulnReport struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Overview string   `json:"overview"`
	Impact   string   `json:"impact"`
	CPEs     []string `json:"cpes"`
	CVEs     []string `json:"cves"`
	CVSSs    []string `json:"cvsss"`
}

// String() は脆弱性レポートデータを文字列化する関数
func (v VulnReport) String() string {
	return fmt.Sprintf(
		"ID:%s\nTitle:%s\nOverview:%s\nImpact:%s\nCPEs:%s\nCVEs:%s\nCVSSs:%s",
		v.ID, v.Title, v.Overview, v.Impact,
		strings.Join(v.CPEs, ","),
		strings.Join(v.CVEs, ","),
		strings.Join(v.CVSSv3(), ","))
}

// CVSSv3 は脆弱性レポートの CVSS のリストの中から CVSSv3 を抜き出す関数
func (v VulnReport) CVSSv3() (r []string) {
	r = pickupCVSSv3(v.CVSSs)
	return
}

// pickupCVSSv3 は与えられた CVSS のリストの中から CVSSv3 を抜き出す関数
func pickupCVSSv3(cvsss []string) (r []string) {
	for _, cvss := range cvsss {
		if strings.HasPrefix(cvss, "CVSS") {
			r = append(r, cvss)
		}
	}
	return
}
