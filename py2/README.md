# vulnspy

Golang で実装した vulns パッケージの Python2 用コネクタ。

----

## 開発環境

### OS の情報

```
[root@iskandar ~]# cat /etc/os-release
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:7"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-7"
CENTOS_MANTISBT_PROJECT_VERSION="7"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="7"

[root@iskandar ~]# uname -a
Linux iskandar 3.10.0-1062.12.1.el7.x86_64 #1 SMP Tue Feb 4 23:02:59 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

### GCC と Python 関連のパッケージ

```
[root@iskandar ~]# rpm -qa | grep -e gcc -e python
python2-rpm-macros-3-32.el7.noarch
python-rpm-macros-3-32.el7.noarch
python-libs-2.7.5-86.el7.x86_64
libselinux-python-2.5-14.1.el7.x86_64
gcc-4.8.5-39.el7.x86_64
python-iniparse-0.4-9.el7.noarch
python-schedutils-0.4-6.el7.x86_64
python-linux-procfs-0.4.11-4.el7.noarch
python-urlgrabber-3.10-9.el7.noarch
dbus-python-1.1.1-9.el7.x86_64
libgcc-4.8.5-39.el7.x86_64
python-perf-3.10.0-1062.12.1.el7.x86_64
python-firewall-0.6.3-2.el7_7.3.noarch
python-srpm-macros-3-32.el7.noarch
python-devel-2.7.5-86.el7.x86_64
python-2.7.5-86.el7.x86_64
python-decorator-3.4.0-3.el7.noarch
python-gobject-base-3.22.0-1.el7_4.1.x86_64
python-slip-0.4.0-4.el7.noarch
newt-python-0.52.15-4.el7.x86_64
python-configobj-4.7.2-7.el7.noarch
python-pycurl-7.19.0-19.el7.x86_64
rpm-python-4.11.3-40.el7.x86_64
python-slip-dbus-0.4.0-4.el7.noarch
python-pyudev-0.15-9.el7.noarch
```

特に python-devel パッケージが必要。

### golang, python, gcc のバージョン

```
[root@iskandar ~]# go version
go version go1.13.8 linux/amd64
[root@iskandar ~]# gcc --version
gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-39)
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

[root@iskandar ~]# python -V
Python 2.7.5
```

golang のインストールには、https://golang.org/doc/install#install を参照のこと。

### pkg-config を使用

Python の C-API を使用するため、Python パッケージのコンパイル設定のヘッダファイルの所在やリンク設定の参照に pkg-config を使用する。

```
[root@iskandar ~]# rpm -qa | grep pkgconfig
pkgconfig-0.27.1-4.el7.x86_64
[root@iskandar ~]# pkg-config python2 --cflags
-I/usr/include/python2.7
[root@iskandar ~]# pkg-config python2 --libs
-lpython2.7
```

----

## ビルド手順

ソースコードを展開したフォルダにて以下のコマンドを実行。

```
go get github.com/bunji2/vulns
go get github.com/bunji2/cvssv3
make
```

同じフォルダに vulnsmodule.so が作成されていれば完了。

----

## API

コマンド

|用途|API|備考|
|:--|:--|:--|
|vulns パッケージのインポート|```import vulns```||
|vulns パッケージの初期化|```vulns.init(configFile)```|configFile は設定ファイルのパス|
|脆弱性レポートの取得|```r=vulns.report('CVE-2019-001002')```|vulns.report の引数は脆弱性レポートの識別子、返り値は脆弱性レポートの項目を格納した dict オブジェクト|
|脆弱性レポートのダイジェストの取得|```d=vulns.digest('CVE-2019-001002')```|vulns.digest の引数は脆弱性レポートの識別子、返り値は脆弱性レポートのダイジェスト項目を格納した dict オブジェクト|

### 脆弱性レポートの項目

|項目|概要|
|:--|:--|
|ID|脆弱性レポートの識別子|
|Title|脆弱性レポートのタイトル|
|Overview|脆弱性の概要|
|Impact|脆弱性の影響|
|CPEs|脆弱性の対象となる CPE のリスト|
|CVSSv3|CVSSv3 のリスト|
|CVEs|CVE のリスト|

### 脆弱性レポートのダイジェストの項目

|項目|概要|
|:--|:--|
|ID|脆弱性レポートの識別子|
|Vulns|脆弱性のキーワードのリスト|
|Impacts|脆弱性の影響キーワードのリスト|
|CPEs|脆弱性の対象となる CPE のリスト|
|CVSSv3|CVSSv3 のリスト|
|Scores|CVSSv3 の BaseScore のリスト|
|CVEs|CVE のリスト|

## 使い方

vulnsmodule.so のあるフォルダで Python スクリプトを実行する。

```
# -*- coding: utf-8 -*-

import vulns

def report(id):
    r = vulns.report(id)
    if len(r)<1:
        print "id %s is not correct"%id
        return
    print "ID =", r['ID']
    print "Title =", r['Title']
    print "Overview =", r['Overview']
    print "Impact =", r['Impact']
    print "CPEs =", ''.join(r['CPEs'])
    print "CVEs =", ''.join(r['CVEs'])
    print "CVSSv3 =", ''.join(r['CVSSv3'])

def digest(id):
    r = vulns.digest(id)
    if len(r)<1:
        print "id %s is not correct"%id
        return
    print "ID =", r['ID']
    print "Vulns =", ','.join(r['Vulns'])
    print "Impacts =", ','.join(r['Impacts'])
    print "CPEs =", ','.join(r['CPEs'])
    print "CVEs =", ','.join(r['CVEs'])
    print "CVSSv3 =", ','.join(r['CVSSv3'])
    print "Scores =", ','.join(r['Scores'])

def main():
    vulns.init("/opt/vulns/config.json")
    report("JVNDB-2018-001002")
    digest("JVNDB-2018-001002")

if __name__ == "__main__":
    main()
```
