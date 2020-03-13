// 脆弱性レポートを取得するパッケージ。使用する脆弱性レポートは JVNを対象とする。

// [MEMO] jvndb から RDF をダウンロードし、脆弱性レポートデータの作成にあたり、
// Golang 標準の XML パーサを使うと大量のメモリを消費するため、メモリ影響をかけない形でパースする。

// [XXX] 以下の問題があるが、すぐには解決できそうにない。
// ・大量のメモリを消費せずに XML をパースするいいライブラリが見つかっていないこと。
// ・従って自前の実装コードで十分にテストができていると断言できず、バグが潜んでいる可能性があること。
// ・JPCERT/CC の実装に依存していること。（これは大丈夫なのではないか、と楽観的にみている）
//   - JVNDB のサイトが出力しているタグの改行の作法に依存しているため、もしも仕様が変更されると全面的な作り直しが発生する。
//   - JVNDB のサイトの URL 仕様に依存しているため、仕様が変更されると urlFmt の修正が必要となる。

package fetch

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
	// 接続先 URL のフォーマット
	urlFmt = "https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_%04d.rdf"
)

// CVEID の正規表現を格納する変数
var regCvePat *regexp.Regexp

// InitConfig はパッケージを初期化しつつ vulns パッケージも初期化する関数
func InitConfig(confFile string) (err error) {
	Init()
	err = vulns.InitConfig(confFile)
	return
}

// Init はパッケージを初期化する関数
func Init() (err error) {
	regCvePat = regexp.MustCompile(`CVE-[0-9]+-[0-9]+`)
	return
}

// Fetch は指定された西暦年の脆弱性レポートを取得する関数
func Fetch(year int) (r []vulns.VulnReport, err error) {
	// year のチェック。ここでしくじると、JVNDB のサイトに無駄なアクセスが発生するので注意。
	// 指定されるべき正しい値は、1998 <= year <=現在の西暦年
	t := time.Now()
	if year > t.Year() || year < 1998 {
		err = fmt.Errorf("abnormal year")
		return
	}

	// 指定された西暦年をもとに URL を作成し接続する。
	url := fmt.Sprintf(urlFmt, year)
	var resp *http.Response
	resp, err = http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// [TODO] コンテンツタイプの確認。
	// が、いまのところコンテンツタイプの確認をしなくても致命的な問題は起きていない。。。

	// レスポンスを一行ずつ処理
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if sc.Err() != nil {
			break
		}
		var record vulns.VulnReport

		// 前後の空白のトリミング
		line := strings.TrimSpace(sc.Text())

		// Vulinfo のタグが見つかったら readVulinfo を呼ぶ。
		// ここが独自パージングの起点。
		if strings.Contains(line, "<Vulinfo>") {
			record, err = readVulinfo(sc)
			// readVulinfo の先の処理の中で、</Vulinfo> まで読み込んでいる（はず）。

			r = append(r, record)
		}
		//fmt.Println(record)
	}

	return
}

// readVulinfo は Vulinfo ノードのパースを行う関数
func readVulinfo(sc *bufio.Scanner) (r vulns.VulnReport, err error) {
	var id, title, overview, impact string
	var cpes, cves, cvsss []string
	for sc.Scan() { // [LOOP1]
		if sc.Err() != nil {
			break
		}
		// 一行読み出し、前後の空白をトリミング
		line := strings.TrimSpace(sc.Text())

		// </Vulinfo> を見つけたら脆弱性レポートデータを作ってループを抜ける。
		if strings.Contains(line, "</Vulinfo>") {
			if id != "" && title != "" && overview != "" && impact != "" {
				// cpes, cves, cvsss は空でもよい
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
			// <Related> を見つけたら cveid を探しにいく
			cves, err = readCVEs(sc)
			if err != nil {
				break
			}
		} else if id == "" && strings.Contains(line, "<VulinfoID>") {
			// <VulinfoID> を見つけたら脆弱性レポートの ID を取り出す
			id = readVulinfoID(line)
		} else if title == "" && strings.Contains(line, "<Title>") {
			// <Title> を見つけたら脆弱性レポートの title を取り出す
			title = readTitle(line)
		} else if overview == "" && strings.Contains(line, "<Overview>") {
			// <Overview> を見つけたら脆弱性レポートの overview を取り出す
			overview = readOverview(line)
		} else if impact == "" && strings.Contains(line, "<Description>") {
			// <Description> を見つけたら脆弱性レポートの impact を取り出す
			impact = readDescription(line)
		} else if strings.Contains(line, "<Vector>") {
			// <Vector> を見つけたら脆弱性レポートの CVSS を取り出す
			cvsss = append(cvsss, readVector(line))
		} else if strings.Contains(line, "<Cpe ") {
			// <Cpe を見つけたら脆弱性レポートの CPE を取り出す
			cpes = append(cpes, readCpe(line))
		}

	} // [LOOP1]

	return
}

// readCVEs は CVEID のリストを読み出す関数
func readCVEs(sc *bufio.Scanner) (cves []string, err error) {
	ids := map[string]int{}
	for sc.Scan() {
		if sc.Err() != nil {
			break
		}
		// 一行読み出し、前後の空白をトリミング
		line := strings.TrimSpace(sc.Text())

		if strings.Contains(line, "</Related>") {
			// "</Related>" が現れたらループを抜ける
			break
		} else if strings.Contains(line, "<VulinfoID>") {
			// "<VulinfoID>" が現れたら CVEID を取り出す。ここ、脆弱性レポートIDとタグが共用だ。
			id := readVulinfoID(line)
			//fmt.Println("id =", id)

			// 取り出した ID の中には複数の CVEID が含まれている可能性があるので、
			// CVEID の正規表現のパターンにマッチさせて取り出す。
			for _, match := range regCvePat.FindAllStringSubmatch(id, -1) {
				//fmt.Println("match =", match)

				// map[string]int の ids に格納しているのは、一意な CVEID にしたいから
				ids[match[0]] = 1
			}
		}
	}
	// map[string]int の ids から、一意な CVEID リストを取り出す
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

// readTextValue は特定のタグで囲まれた文字列を取り出す関数。
func readTextValue(tag, line string) (r string) {
	idx := strings.Index(line, tag)
	if idx < 0 {
		return
	}

	// "<XXX>SSS</" のようなパターンのときに、SSS の部分だけを取り出す処理
	line = line[idx+len(tag):]
	idx = strings.LastIndex(line, "</")
	if idx < 0 {
		return
	}
	r = line[0:idx]

	// あとで CSV 化することも想定して二重引用符とカンマは空白に変換
	r = strings.ReplaceAll(r, `"`, ` `)
	r = strings.ReplaceAll(r, `,`, ` `)

	// 前後の空白のトリミングはここではやらない
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
