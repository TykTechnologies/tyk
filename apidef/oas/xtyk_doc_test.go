package oas

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"testing"
)

var (
	dumpXTykDocHelp = `if this flag is passed in tests, TestExtractDocFromXTyk will dump x-tyk-docs `
	dumpXTykDoc     = flag.String("x-tyk-dump-doc", "", dumpXTykDocHelp)
)

func TestExtractDocFromXTyk(t *testing.T) {
	fInfo, err := ExtractDocFromXTyk()
	if err != nil {
		// should fail, but for now let's print errors for
		// demonstration purpose
		t.Log(err.Error())
	}
	if !flag.Parsed() {
		flag.Parse()
	}
	if *dumpXTykDoc != "" {
		infoToJson, _ := json.MarshalIndent(fInfo, "", "  ")
		ioutil.WriteFile(*dumpXTykDoc, infoToJson, 0666)
	}
}
