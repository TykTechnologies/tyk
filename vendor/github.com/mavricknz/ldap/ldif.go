package ldap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
)

const (
	AddRecord    = 0
	ModifyRecord = 1
	ModDnRecord  = 2
	ModRdnRecord = 3
	DeleteRecord = 4
	EntryRecord  = 255
)

var LDIFDebug bool = false

var attrValueSep []byte = []byte{':'}
var versionRegex *regexp.Regexp
var charsetRegex *regexp.Regexp

var stdBase64 *base64.Encoding

func init() {
	versionRegex = regexp.MustCompile(`^version:\s+(\d+)`)
	charsetRegex = regexp.MustCompile(`^charset:\s+([^ ]+)`)
	stdBase64 = base64.StdEncoding
}

type LDIFRecord interface {
	RecordType() uint8
}

type LDIFReader struct {
	Version string
	Charset string
	Reader  *bufio.Reader

	NoMoreEntries bool
	EntryCount    uint64
	LineCount     uint64
}

func NewLDIFReader(reader io.Reader) (*LDIFReader, error) {
	lr := &LDIFReader{Reader: bufio.NewReader(reader)}
	return lr, nil
}

func (lr *LDIFReader) ReadLDIFEntry() (LDIFRecord, error) {
	if lr.NoMoreEntries {
		return nil, nil
	}
	ldiflines, err := lr.readLDIFEntryIntoSlice()
	if err != nil {
		return nil, err
	}
	if ldiflines == nil {
		return nil, nil
	}

	if bytes.EqualFold(ldiflines[0][0:7], []byte("version")) {
		lr.Version = string(versionRegex.Find(ldiflines[0]))
		return lr.ReadLDIFEntry()
	}
	if bytes.EqualFold(ldiflines[0][0:7], []byte("charset")) {
		lr.Charset = string(charsetRegex.Find(ldiflines[0]))
		return lr.ReadLDIFEntry()
	}
	return sliceToLDIFRecord(ldiflines)
}

func sliceToLDIFRecord(lines [][]byte) (LDIFRecord, error) {
	var dn string
	var dataLineStart int // better name, after dn/controls/changetype
	controls := make([]Control, 0)
	recordtype := EntryRecord
LINES:
	for i, line := range lines {
		attrName, value, _, err := findAttrAndValue(line)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0 && bytes.EqualFold(attrName, []byte("dn")):
			dn = string(value)
			continue LINES
		case i == 0 && !bytes.EqualFold(attrName, []byte("dn")):
			return nil, NewLDAPError(ErrorLDIFRead, "'dn:' not at the start of line in LDIF record")
		case bytes.EqualFold(attrName, []byte("changetype")):
			switch strings.ToLower(string(value)) {
			// check the record type, if one.
			case "add":
				recordtype = AddRecord
			case "modify":
				recordtype = ModifyRecord
			case "moddn":
				recordtype = ModDnRecord
			case "modrdn":
				recordtype = ModRdnRecord
			case "delete":
				recordtype = DeleteRecord

			}
			continue LINES
		case bytes.EqualFold(attrName, []byte("control")):
			//TODO handle controls
			continue LINES
		}
		dataLineStart = i
		break
	}
	// TODO - add the missing record types
	unsupportedError := NewLDAPError(ErrorLDIFRead, "Unsupported LDIF record type")
	switch recordtype {
	case AddRecord:
		addEntry, err := ldifLinesToEntryRecord(dn, lines[dataLineStart:])
		if err != nil {
			return nil, err
		}
		addRequest := AddRequest{Entry: addEntry, Controls: controls}
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, AddRecord, dataLineStart)
		}
		return &addRequest, nil
	case ModifyRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModifyRecord, dataLineStart)
		}
		modRequest, err := ldifLinesToModifyRecord(dn, lines[dataLineStart:])
		if err != nil {
			return nil, err
		}
		modRequest.Controls = controls
		return modRequest, nil
	case ModDnRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModDnRecord, dataLineStart)
		}
		return nil, unsupportedError
	case ModRdnRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, ModRdnRecord, dataLineStart)
		}
		return nil, unsupportedError
	case DeleteRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, DeleteRecord, dataLineStart)
		}
		deleteRequest := NewDeleteRequest(dn)
		for _, control := range controls {
			deleteRequest.AddControl(control)
		}
		return deleteRequest, nil
	case EntryRecord:
		if LDIFDebug {
			log.Printf("dn: %s, changetype: %d, datastart: %d\n", dn, EntryRecord, dataLineStart)
		}
		return ldifLinesToEntryRecord(dn, lines[dataLineStart:])
	}
	return nil, NewLDAPError(ErrorLDIFRead, "Unkown LDIF record type")
}

func ldifLinesToModifyRecord(dn string, lines [][]byte) (*ModifyRequest, error) {
	modReq := NewModifyRequest(dn)
	var currentModType uint8
	var currentAttrName string
	var newMod *Mod

	isNewMod := true

	for _, line := range lines {
		bAttr, bValue, sep, err := findAttrAndValue(line)
		if err != nil {
			return nil, err
		}
		if sep {
			if newMod == nil {
				return nil, NewLDAPError(ErrorLDIFRead, "Misplaced '-'?")
			}
			modReq.AddMod(newMod)
			isNewMod = true
			continue
		}
		attrOrOpLower := strings.ToLower(string(bAttr))
		if isNewMod { // current line should be "operation: attr"
			switch {
			case attrOrOpLower == "add":
				currentModType = ModAdd
			case attrOrOpLower == "delete":
				currentModType = ModDelete
			case attrOrOpLower == "replace":
				currentModType = ModReplace
			case attrOrOpLower == "increment":
				currentModType = ModIncrement
			case true:
				return nil, NewLDAPError(ErrorLDIFRead, "Expecting Modtype, not found.")
			}
			currentAttrName = string(bValue)
			isNewMod = false
			newMod = NewMod(currentModType, currentAttrName, nil)
		} else {
			attrName := string(bAttr)
			if currentAttrName != attrName {
				return nil, NewLDAPError(ErrorLDIFRead,
					fmt.Sprintf("AttrName mismatch %s != %s", currentAttrName, attrName))
			}
			attrValue := string(bValue)
			// could check for empty values but some servers accept them
			newMod.Modification.Values = append(newMod.Modification.Values, attrValue)
		}
	}
	if isNewMod == false {
		modReq.AddMod(newMod)
	}
	return modReq, nil
}

func ldifLinesToEntryRecord(dn string, lines [][]byte) (*Entry, error) {
	entry := NewEntry(dn)
	for _, line := range lines {
		bAttr, bValue, separator, err := findAttrAndValue(line)
		if err != nil {
			return nil, err
		}
		if separator {
			continue // -
		}
		attributeName := string(bAttr)
		entry.AddAttributeValue(attributeName, string(bValue))
		//log.Printf("processed: %s: %s\n", attr, string(bValue))
	}
	//fmt.Println(entry)
	return entry, nil
}

func findAttrAndValue(line []byte) (attr []byte, value []byte, separator bool, err error) {
	var valueStart int
	colonLoc := bytes.Index(line, attrValueSep)
	base64 := false
	if line[0] == '-' {
		separator = true
		return
	}
	// find the location of first ':'
	if colonLoc == -1 {
		return nil, nil, false, NewLDAPError(ErrorLDIFRead, ": not found in LDIF attr line.")
	} else if line[colonLoc+1] == ':' { // base64 attr
		valueStart = colonLoc + 2
		if line[colonLoc+2] == ' ' {
			valueStart = colonLoc + 3
		}
		base64 = true
	} else { // normal
		valueStart = colonLoc + 1
		if line[colonLoc+1] == ' ' { // accomidate attr:value
			valueStart = colonLoc + 2
		}
	}

	attr = line[:colonLoc]

	if base64 {
		value, err = decodeBase64(line[valueStart:])
		if err != nil {
			return nil, nil, false, NewLDAPError(ErrorLDIFRead, "Error decoding base64 value")
		}
	} else {
		value = line[valueStart:]
	}
	if LDIFDebug {
		log.Printf("findAttrAndValue: attr: [%s]", attr)
		log.Printf("findAttrAndValue:value: [%s]", string(value))
	}
	return
}

func (lr *LDIFReader) readLDIFEntryIntoSlice() ([][]byte, error) {
	entry := make([][]byte, 0, 10)
	linecount := -1
ENTRY:
	for {
		line, err := lr.Reader.ReadBytes('\n')
		// fmt.Printf("len=%d, err=%v, %s", len(line), err, line)
		if err != nil {
			if err == io.EOF {
				lr.NoMoreEntries = true
				if len(entry) == 0 {
					return nil, nil
				}
				break
			}
			return nil, err
		}
		lr.LineCount++
		if line[0] == '\n' || (line[0] == '\r' && line[1] == '\n') {
			if len(entry) == 0 {
				continue ENTRY
			}
			break
		}
		if line[0] == '#' { // comments
			continue ENTRY
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation
			if line[len(line)-2] == '\r' {
				entry[linecount] = append(entry[linecount], line[1:len(line)-2]...) // strip two bytes
			} else {
				entry[linecount] = append(entry[linecount], line[1:len(line)-1]...)
			}
			continue ENTRY
		}
		linecount++
		if line[len(line)-2] == '\r' {
			entry = append(entry, line[:len(line)-2]) // strip two bytes
		} else {
			entry = append(entry, line[:len(line)-1])
		}
		if err != nil {
			break ENTRY
		}
	}
	//for i, line := range entry {
	//	fmt.Println(i)
	//	fmt.Println(hex.Dump(line))
	//}
	return entry, nil
}

func decodeBase64(encodedBytes []byte) ([]byte, error) {
	decodedValue := make([]byte, stdBase64.DecodedLen(len(encodedBytes)))
	count, err := stdBase64.Decode(decodedValue, encodedBytes)
	if err != nil || count == 0 {
		return nil, NewLDAPError(ErrorLDIFRead, "Error decoding base64 value")
	}
	return decodedValue[:count], nil
}
