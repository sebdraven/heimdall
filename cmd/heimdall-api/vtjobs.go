package main

import (
	"strconv"
	"time"

	"github.com/sebdraven/heimdall/internal/vt"
)

const vtJobTimeout = 10 * time.Minute

// vtJob is the state of a VirusTotal enrichment.
type vtJob = job[vt.Summary]

func domainTarget(fqdn string) string { return "domain:" + fqdn }

func campaignTarget(id int64) string { return "campaign:" + strconv.FormatInt(id, 10) }

func ipTarget(ip string) string { return "ip:" + ip }
