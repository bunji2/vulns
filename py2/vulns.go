package main

// #cgo pkg-config: python2
// #cgo LDFLAGS: subvulns.o
// #include "subvulns.h"
import "C"
import (
	"fmt"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/digest"
)

// dummy main
func main() {}

const (
	cOK = C.int(0)
	cNG = C.int(-1)
)

//export vulnsInit
func vulnsInit(confFile *C.char) C.int {
	gConfFile := C.GoString(confFile)
	err := vulns.InitConfig(gConfFile)
	if err != nil {
		return cNG
	}
	err = digest.InitConfig(gConfFile)
	if err != nil {
		return cNG
	}
	return cOK
}

//export vulnsReport
func vulnsReport(id *C.char, dict *C.PyObject) C.int {
	r, err := vulns.LoadVulnReportFromID(C.GoString(id))
	if err != nil {
		return cNG
	}
	strItems := [][]string{
		[]string{"ID", r.ID},
		[]string{"Title", r.Title},
		[]string{"Overview", r.Overview},
		[]string{"Impact", r.Impact},
	}
	for _, item := range strItems {
		if C.dictSetStr(dict, C.CString(item[0]), C.CString(item[1])) < 0 {
			return cNG
		}
	}
	if dictSetList(dict, "CPEs", r.CPEs) < cOK {
		return cNG
	}
	if dictSetList(dict, "CVEs", r.CVEs) < cOK {
		return cNG
	}
	if dictSetList(dict, "CVSSv3", r.CVSSv3()) < cOK {
		return cNG
	}
	return cOK
}

//export vulnsDigest
func vulnsDigest(id *C.char, dict *C.PyObject) C.int {
	r, err := vulns.LoadVulnReportFromID(C.GoString(id))
	if err != nil {
		return cNG
	}
	d := digest.Digest(r)
	if C.dictSetStr(dict, C.CString("ID"), C.CString(d.ID)) < 0 {
		return cNG
	}
	if dictSetList(dict, "CPEs", d.CPEs) < cOK {
		return cNG
	}
	if dictSetList(dict, "CVEs", d.CVEs) < cOK {
		return cNG
	}
	if dictSetList(dict, "CVSSv3", d.CVSSv3()) < cOK {
		return cNG
	}
	if dictSetList(dict, "Vulns", d.UniqueVulns()) < cOK {
		return cNG
	}
	if dictSetList(dict, "Impacts", d.Impacts) < cOK {
		return cNG
	}
	if dictSetList(dict, "Scores", convFloat2Str(d.BaseScores())) < cOK {
		return cNG
	}
	return cOK
}

func dictSetList(dict *C.PyObject, key string, strList []string) C.int {
	tmp := C.newList()
	for _, str := range strList {
		if C.listAppendStr(tmp, C.CString(str)) < 0 {
			return cNG
		}
	}
	if C.dictSetObj(dict, C.CString(key), tmp) < 0 {
		return cNG
	}
	return cOK
}

func convFloat2Str(xx []float64) (r []string) {
	for _, x := range xx {
		r = append(r, fmt.Sprintf("%.1f", x))
	}
	return
}
