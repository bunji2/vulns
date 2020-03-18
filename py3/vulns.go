package main

/*
#cgo pkg-config: python3
#include "Python.h"
*/
import "C"
import "fmt"
import "github.com/bunji2/vulns"
import "github.com/bunji2/vulns/digest"

// dummy main
func main(){}

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

    strItems := [][]string {
        []string{"ID",r.ID},
        []string{"Title",r.Title},
        []string{"Overview",r.Overview},
        []string{"Impact",r.Impact},
    }
	for _, item := range strItems {
            k := C.CString(item[0])
	    v := C.PyUnicode_FromString(C.CString(item[1]))
	    if C.PyDict_SetItemString(dict, k, v)<0 {
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
	k := C.CString("ID")
        v := C.PyUnicode_FromString(C.CString(d.ID))
	if C.PyDict_SetItemString(dict, k, v)<0 {
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
        tmp := C.PyList_New(C.Py_ssize_t(0));
	for _, str := range strList {
            if C.PyList_Append(tmp, C.PyUnicode_FromString(C.CString(str)))<0 {
                return cNG
	    }
	}
        if (C.PyDict_SetItemString(dict, C.CString(key), tmp)<0) {
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
//-I/usr/include/python3.6m -I/usr/include/python3.6m  -Wno-unused-result -Wsign-compare -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -D_GNU_SOURCE -fPIC -fwrapv   -DNDEBUG -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -D_GNU_SOURCE -fPIC -fwrapv
// -L/usr/lib64 -lpython3.6m -lpthread -ldl  -lutil -lm  -Xlinker -export-dynamic
//#cgo CFLAGS: -I/usr/include/python3.6m -I/usr/include/python3.6m  -Wno-unused-result -Wsign-compare -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -D_GNU_SOURCE -fPIC -DNDEBUG -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -D_GNU_SOURCE -fPIC
//#cgo LDFLAGS: -L/usr/lib64 -lpython3.6m -lpthread -ldl  -lutil -lm
