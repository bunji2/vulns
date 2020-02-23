// JVN の脆弱性レポートを取得するパッケージ

// [MEMO] jvndb から RDF をダウンロードし、脆弱性レポートデータの作成にあたり、
// Golang 標準の XML パーサを使うと大量のメモリを消費するため、メモリ影響をかけない形でパースする。

package jvn

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bunji2/vulns"
)

const (
	urlFmt = "https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_%04d.rdf"
)

var regCvePat *regexp.Regexp

// Init はパッケージを初期化する関数
func Init() (err error) {
	regCvePat = regexp.MustCompile(`CVE-[0-9]+-[0-9]+`)
	return
}

// Fetch は指定された西暦年の脆弱性レポートを取得する関数
func Fetch(year int) (r []vulns.VulnReport, err error) {
	// year のチェック
	t := time.Now()
	if year > t.Year() || year < 1998 {
		err = fmt.Errorf("abnormal year")
		return
	}

	url := fmt.Sprintf(urlFmt, year)
	var resp *http.Response
	resp, err = http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// [TODO] コンテンツタイプの確認。

	// レスポンスを一行ずつ処理
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if sc.Err() != nil {
			break
		}
		var record vulns.VulnReport
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "<Vulinfo>") {
			record, err = readVulinfo(sc)
			r = append(r, record)
		}
		//fmt.Println(record)
	}

	return
}

func readVulinfo(sc *bufio.Scanner) (r vulns.VulnReport, err error) {
	var id, title, overview, impact string
	var cpes, cves, cvsss []string
	for sc.Scan() {
		if sc.Err() != nil {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "</Vulinfo>") {
			if id != "" && title != "" && overview != "" && impact != "" {
				r = vulns.VulnReport{
					ID:       id,
					Title:    title,
					Overview: overview,
					Impact:   impact,
					CPEs:     cpes,
					CVEs:     cves,
					CVSSs:    cvsss,
				}
			}
			break
		} else if strings.Contains(line, "<Related>") {
			cves, err = readCVEs(sc)
			if err != nil {
				break
			}
		} else if id == "" && strings.Contains(line, "<VulinfoID>") {
			id = readVulinfoID(line)
		} else if title == "" && strings.Contains(line, "<Title>") {
			title = readTitle(line)
		} else if overview == "" && strings.Contains(line, "<Overview>") {
			overview = readOverview(line)
		} else if impact == "" && strings.Contains(line, "<Description>") {
			impact = readDescription(line)
		} else if strings.Contains(line, "<Vector>") {
			cvsss = append(cvsss, readVector(line))
		} else if strings.Contains(line, "<Cpe ") {
			cpes = append(cpes, readCpe(line))
		}
	}
	return
}

func readCVEs(sc *bufio.Scanner) (cves []string, err error) {
	ids := map[string]int{}
	for sc.Scan() {
		if sc.Err() != nil {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "</Related>") {
			break
		} else if strings.Contains(line, "<VulinfoID>") {
			id := readVulinfoID(line)
			//fmt.Println("id =", id)
			for _, match := range regCvePat.FindAllStringSubmatch(id, -1) {
				//for _, match := range regCvePat.FindAllStringSubmatch(line, -1) {
				//fmt.Println("match =", match)
				ids[match[0]] = 1
			}
			/*
				if strings.HasPrefix(id, "CVE-") {
					ids[id] = 1
				}
			*/
		}
	}
	for id := range ids {
		cves = append(cves, id)
	}
	return
}

func readVulinfoID(line string) (r string) {
	r = readTextValue("<VulinfoID>", line)
	return
}

func readTitle(line string) (r string) {
	r = readTextValue("<Title>", line)
	return
}

func readOverview(line string) (r string) {
	r = readTextValue("<Overview>", line)
	return
}

func readDescription(line string) (r string) {
	r = readTextValue("<Description>", line)
	return
}

func readVector(line string) (r string) {
	r = readTextValue("<Vector>", line)
	return
}

func readCpe(line string) (r string) {
	r = readTextValue(`<Cpe version="2.2">`, line)
	return
}

func readTextValue(tag, line string) (r string) {
	idx := strings.Index(line, tag)
	if idx < 0 {
		return
	}
	line = line[idx+len(tag):]
	idx = strings.LastIndex(line, "</")
	if idx < 0 {
		return
	}
	r = line[0:idx]
	r = strings.ReplaceAll(r, `"`, ` `)
	r = strings.ReplaceAll(r, `,`, ` `)
	return
}

/*

[MEMO] JVNDB のデータ構造

 ・URL は以下の形式
https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_2019.rdf

・必要な要素

基本ノード単位：/VULDEF-Document/Vulinfo

項目：
識別子：VulinfoID
タイトル：VulinfoData/Title
概要：VulinfoData/VulinfoDescription
影響：VulinfoData/Impact/ImpactItem/Description
CPE: [VulinfoData/Affected/AffectedItem/Cpe]
Cvss: [VulinfoData/Impact/Cvss/{Vector,Base}]
CVE: VulinfoData/RelatedItem@type="advisory"/VulinfoID ※"CVE"ではじまるばあい


<VULDEF-Document>
    <Vulinfo>
      <VulinfoID>JVNDB-2019-001004</VulinfoID>
      <VulinfoData>
        <Title>オムロン製 CX-One に任意のコード実行が可能な脆弱性</Title>
        <VulinfoDescription>
          <Overview>オムロン株式会社が提供する CX-One には、任意のコードが実行可能な脆弱性が存在します。  オムロン株式会社が提供する CX-One の CX-Protocol には、プロジェクトファイルを処理する際の、型の取り違え (CWE-843) に起因する、任意のコードが実行可能な脆弱性が存在します。  </Overview>
        </VulinfoDescription>
        <Affected>
          <AffectedItem>
            <Name>オムロン株式会社</Name>
            <ProductName>CX-One</ProductName>
            <Cpe version="2.2">cpe:/a:omron:cx-one</Cpe>
            <VersionNumber>Version 4.50 およびそれ以前 </VersionNumber>
          </AffectedItem>
          <AffectedItem>
            <Name>オムロン株式会社</Name>
            <ProductName>CX-Protocol</ProductName>
            <Cpe version="2.2">cpe:/a:omron:cx-protocol</Cpe>
            <VersionNumber>Version 2.0 およびそれ以前</VersionNumber>
          </AffectedItem>
        </Affected>
        <Impact>
          <Cvss version="2.0">
            <Severity type="Base">Medium</Severity>
            <Base>5.4</Base>
            <Vector>AV:A/AC:M/Au:N/C:P/I:P/A:P</Vector>
          </Cvss>
          <Cvss version="3.0">
            <Severity type="Base">Medium</Severity>
            <Base>6.6</Base>
            <Vector>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H</Vector>
          </Cvss>
          <ImpactItem>
            <Description>細工されたプロジェクトファイルを処理することで、第三者によってアプリケーションの権限で任意のコードを実行される可能性があります。</Description>
          </ImpactItem>
        </Impact>
        <Solution>
          <SolutionItem>
            <Description>[アップデートする] 開発者が提供する情報をもとに、最新版へアップデートしてください。 </Description>
          </SolutionItem>
        </Solution>
        <Related>
          <RelatedItem type="vendor">
            <Name>OMRON</Name>
            <VulinfoID>CX-One バージョンアップ プログラム ダウンロード</VulinfoID>
            <URL>https://www.fa.omron.co.jp/product/tool/26/cxone/one1.html</URL>
          </RelatedItem>
          <RelatedItem type="vendor">
            <Name>OMRON</Name>
            <VulinfoID>CX-Protocol の更新内容: Ver.2.01 : CX-Oneオートアップデート（V4向け_2019年1月）</VulinfoID>
            <URL>https://www.fa.omron.co.jp/product/tool/26/cxone/j4_doc.html#cx_protocol</URL>
          </RelatedItem>
          <RelatedItem type="advisory">
            <Name>Common Vulnerabilities and Exposures (CVE)</Name>
            <VulinfoID>CVE-2018-19027</VulinfoID>
            <URL>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19027</URL>
          </RelatedItem>
          <RelatedItem type="advisory">
            <Name>ICS-CERT ADVISORY</Name>
            <VulinfoID>ICSA-19-010-02</VulinfoID>
            <URL>https://ics-cert.us-cert.gov/advisories/ICSA-19-010-02</URL>
          </RelatedItem>
          <RelatedItem type="advisory">
            <Name>JVN</Name>
            <VulinfoID>JVNVU#97716739</VulinfoID>
            <URL>https://jvn.jp/vu/JVNVU97716739/</URL>
          </RelatedItem>
          <RelatedItem type="advisory">
            <Name>National Vulnerability Database (NVD)</Name>
            <VulinfoID>CVE-2018-19027</VulinfoID>
            <URL>https://nvd.nist.gov/vuln/detail/CVE-2018-19027</URL>
          </RelatedItem>
          <RelatedItem type="cwe">
            <Name>JVNDB</Name>
            <VulinfoID>CWE-843</VulinfoID>
            <Title>型の取り違え</Title>
            <URL>https://cwe.mitre.org/data/definitions/843.html</URL>
          </RelatedItem>
        </Related>
        <History>
          <HistoryItem>
            <HistoryNo>1</HistoryNo>
            <DateTime>2019-01-15T17:46:36+09:00</DateTime>
            <Description>[2019年01月15日]\n  掲載</Description>
          </HistoryItem>
          <HistoryItem>
            <HistoryNo>2</HistoryNo>
            <DateTime>2019-04-03T15:59:33+09:00</DateTime>
            <Description>[2019年04月03日]\n  CVSS による深刻度：内容を更新</Description>
          </HistoryItem>
          <HistoryItem>
            <HistoryNo>3</HistoryNo>
            <DateTime>2019-08-27T14:14:44+09:00</DateTime>
            <Description>[2019年08月27日]\n  参考情報：National Vulnerability Database (NVD) (CVE-2018-19027) を追加</Description>
          </HistoryItem>
        </History>
        <DateFirstPublished>2019-01-15T17:46:36+09:00</DateFirstPublished>
        <DateLastUpdated>2019-08-27T17:43:32+09:00</DateLastUpdated>
        <DatePublic>2019-01-11T00:00:00+09:00</DatePublic>
      </VulinfoData>
    </Vulinfo>

*/
