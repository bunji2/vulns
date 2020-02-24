package main

import (
	"fmt"

	"github.com/bunji2/vulns"
	"github.com/bunji2/vulns/digest"
)

const (
	cmdDigestFmt = "id [ id ... ]\n"
)

func processDigest(args []string) (err error) {

	if len(args) < 1 {
		err = fmt.Errorf("too few arguments")
		return
	}
	ids := args

	var c digest.Config
	c, err = digest.LoadConfig(confFile)
	if err != nil {
		return
	}

	err = digest.Init(c)
	if err != nil {
		return
	}

	err = vulns.Init(vulns.Config{
		DataFolder: c.DataFolder,
		UseGzip:    c.UseGzip,
	})
	if err != nil {
		return
	}

	for _, id := range ids {
		err = _processDigest(id)
		if err != nil {
			return
		}
	}

	return
}

func _processDigest(id string) (err error) {
	var r vulns.VulnReport
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}
	//fmt.Println(r)
	d := digest.Digest(r)
	fmt.Println("----")
	fmt.Println(d)
	return
}
