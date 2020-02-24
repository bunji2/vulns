package main

import (
	"fmt"

	"github.com/bunji2/vulns"
)

const (
	cmdReportFmt = "id [ id ... ]\n"
)

func processReport(args []string) (err error) {

	if len(args) < 1 {
		err = fmt.Errorf("too few arguments")
		return
	}
	ids := args

	var c vulns.Config
	c, err = vulns.LoadConfig(confFile)
	if err != nil {
		return
	}

	err = vulns.Init(c)
	if err != nil {
		return
	}

	for _, id := range ids {
		err = _processReport(id)
		if err != nil {
			return
		}
	}

	return
}

func _processReport(id string) (err error) {
	var r vulns.VulnReport
	r, err = vulns.LoadVulnReportFromID(id)
	if err != nil {
		return
	}
	fmt.Println("----")
	fmt.Println(r)
	return
}
