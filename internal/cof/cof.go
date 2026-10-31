// Package cof implements the Passive DNS Common Output Format
// (draft-dulaunoy-dnsop-passive-dns-cof).
package cof

import (
	"encoding/json"
	"io"
	"time"
)

const ContentType = "application/x-ndjson"

type Record struct {
	RRName    string `json:"rrname"`
	RRType    string `json:"rrtype"`
	RData     string `json:"rdata"`
	TimeFirst int64  `json:"time_first"`
	TimeLast  int64  `json:"time_last"`
	Count     uint64 `json:"count"`
}

func New(rrname, rrtype, rdata string, first, last time.Time, count uint64) Record {
	return Record{
		RRName:    rrname,
		RRType:    rrtype,
		RData:     rdata,
		TimeFirst: first.Unix(),
		TimeLast:  last.Unix(),
		Count:     count,
	}
}

type Writer struct{ enc *json.Encoder }

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Writer{enc: enc}
}

func (w *Writer) Write(r Record) error {
	return w.enc.Encode(r)
}
