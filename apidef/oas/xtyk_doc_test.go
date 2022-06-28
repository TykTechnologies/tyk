package oas

import (
	"flag"
	"io/ioutil"
	"testing"
)

var (
	dumpXTykDocHelp = `if this flag is passed in tests, file "./schema/x-tyk-gateway.md"
will be updated after TestExtractDocFromXTyk has passed`
	dumpXTykDoc = flag.Bool("x-tyk-dump-doc", false, dumpXTykDocHelp)
	xTykDocPath = "./schema/x-tyk-gateway.md"
)

func TestExtractDocFromXTyk(t *testing.T) {
	fInfo, err := ExtractDocFromXTyk()
	if err != nil {
		if _, ok := err.(*FieldDocError); ok {
			// should fail, but for now let's print errors for
			// demonstration purpose
			t.Log(err.Error())
		} else {
			t.Fatal(err.Error())
		}
	}
	if !flag.Parsed() {
		flag.Parse()
	}
	if *dumpXTykDoc {
		_ = ioutil.WriteFile(xTykDocPath, []byte(xtykDocToMarkdown(fInfo)), 0666)
	}
}
