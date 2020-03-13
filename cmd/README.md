# vulns コマンド

脆弱性レポートを操作するコマンド

# 使用方法

```
$ ./vulns help
Vulns Help
 vulns fetch YYYY [ csv out.csv | json ]
    YYYY年の脆弱性レポート群を CSV あるいは JSON で取得
 vulns digest id [ ... ]
    識別番号 id の脆弱性レポートのダイジェストを表示
 vulns report id [ ... ]
    識別番号 id の脆弱性レポートの表示
 vulns help
    この HELP の表示
 vulns version
    バージョンの表示
```

# 設定ファイル

実行ファイルと同じフォルダの "config.json"。

```
{
	"describe": "設定ファイルサンプル",
	"data_folder": "/opt/vulns/data",
	"rule_folder": "/opt/vulns/rules",
   "use_gzip": true
}
```

# BUILD

```
go get github.com/bunji2/vulns
go get github.com/bunji2/cvssv3
go build -o vulns
```
