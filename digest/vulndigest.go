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
	cvss := ""
	score := ""
	cvsss := pickupCVSSv3(d.CVSSs)
	if len(cvsss) > 0 {
		v, e := cvssv3.ParseVector(cvsss[0])
		if e == nil {
			score = fmt.Sprintf("\nScore:%4.1f", v.BaseScore())
		}
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

// pickupCVSSv3 は与えられた CVSS のリストの中から CVSSv3 を抜き出す関数
func pickupCVSSv3(cvsss []string) (r []string) {
	for _, cvss := range cvsss {
		if strings.HasPrefix(cvss, "CVSS") {
			r = append(r, cvss)
		}
	}
	return
}
