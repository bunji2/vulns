package digest

import (
	"fmt"
	"strings"

	"github.com/bunji2/cvssv3"
)

// VulnDigest は脆弱性レポートのダイジェストの型
type VulnDigest struct {
	ID       string   `json:"id"`
	CPEs     []string `json:"cpes"`
	CVEs     []string `json:"cves"`
	CVSSs    []string `json:"cvsss"`
	MainVuln string   `json:"main_vuln"`
	Vulns    []string `json:"vulns"`
	Impacts  []string `json:"impacts"`
}

func (d VulnDigest) String() string {
	vulns := d.UniqueVulns()
	/*
		vulnMap := map[string]bool{}
		for _, vuln := range d.Vulns {
			vulnMap[vuln] = true
		}
		vulns := []string{}
		if d.MainVuln != "" {
			vulns = append(vulns, d.MainVuln)
		}
		for vuln := range vulnMap {
			vulns = append(vulns, vuln)
		}
	*/
	cvss := ""
	score := ""
	//cvsss := pickupCVSSv3(d.CVSSs)
	cvsss := d.CVSSv3()
	if len(cvsss) > 0 {
		var strScores []string
		for _, floatScore := range d.BaseScores() {
			strScores = append(strScores, fmt.Sprintf("%.1f", floatScore))
		}
		score = "\nScore:" + strings.Join(strScores, ",")
		/*		v, e := cvssv3.ParseVector(cvsss[0])
				if e == nil {
					score = fmt.Sprintf("\nScore:%4.1f", v.BaseScore())
				}
		*/
		cvss = "\n" + strings.Join(cvsss, ",")
	}
	cve := ""
	if len(d.CVEs) > 0 {
		cve = "\nCVE:" + strings.Join(d.CVEs, ",")
	}
	return fmt.Sprintf(
		"ID:%s\nCPE:%s\nVulns:%s\nImpacts:%s%s%s%s",
		d.ID,
		strings.Join(d.CPEs, ","),
		strings.Join(vulns, ","),
		strings.Join(d.Impacts, ","),
		score,
		cvss,
		cve,
	)
}

// UniqueVulns は一意な脆弱性キーワードを抽出する関数
func (d VulnDigest) UniqueVulns() (r []string) {
	vulnMap := map[string]bool{}
	for _, vuln := range d.Vulns {
		vulnMap[vuln] = true
	}
	if d.MainVuln != "" {
		r = append(r, d.MainVuln)
	}
	for vuln := range vulnMap {
		r = append(r, vuln)
	}
	return
}

// BaseScores は脆弱性レポートの CVSSv3 のベーススコアを計算する関数
func (d VulnDigest) BaseScores() (scores []float64) {
	for _, cvss := range d.CVSSv3() {
		score := float64(-1)
		v, e := cvssv3.ParseVector(cvss)
		if e == nil {
			score = v.BaseScore()
		}
		scores = append(scores, score)
	}
	return
}

// CVSSv3 は脆弱性レポートの CVSSv3 を抽出する関数
func (d VulnDigest) CVSSv3() (r []string) {
	r = pickupCVSSv3(d.CVSSs)
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
