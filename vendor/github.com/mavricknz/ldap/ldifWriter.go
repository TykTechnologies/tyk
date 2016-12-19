package ldap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"strings"
)

var changetype = "changetype"
var ldifSep string = ":"
var lineSep string = "\n"

type LDIFWriter struct {
	Writer      *bufio.Writer
	EncAsBinary func(string) bool
	LineCount   uint64
	recordCount uint64
}

func NewLDIFWriter(writer io.Writer) (*LDIFWriter, error) {
	lw := &LDIFWriter{
		Writer:      bufio.NewWriter(writer),
		EncAsBinary: IsBinary,
	}
	return lw, nil
}

func (lw *LDIFWriter) WriteLDIFRecord(record LDIFRecord) error {
	// TODO: Controls for all.
	if record == nil {
		return NewLDAPError(ErrorLDIFWrite, "nil record")
	}
	switch record.RecordType() {
	case AddRecord:
		rec := record.(*AddRequest)
		if err := lw.writeDN(rec.Entry.DN); err != nil {
			return err
		}
		if err := lw.writeAttrLine(changetype, "add"); err != nil {
			return err
		}
		if err := lw.writeEntry(rec.Entry); err != nil {
			return err
		}

	case ModifyRecord:
		rec := record.(*ModifyRequest)
		if err := lw.writeDN(rec.DN); err != nil {
			return err
		}
		if err := lw.writeAttrLine(changetype, "modify"); err != nil {
			return err
		}
		if err := lw.writeMods(rec.Mods); err != nil {
			return err
		}

	case ModDnRecord:
		//TODO
	case ModRdnRecord:
		//TODO
	case DeleteRecord:
		rec := record.(*DeleteRequest)

		if err := lw.writeDN(rec.DN); err != nil {
			return err
		}
		if err := lw.writeAttrLine(changetype, "delete"); err != nil {
			return err
		}

	case EntryRecord:
		rec := record.(*Entry)
		if err := lw.writeDN(rec.DN); err != nil {
			return err
		}
		if err := lw.writeEntry(rec); err != nil {
			return err
		}

	}
	// blank line between records.
	if _, werr := lw.Writer.WriteString(lineSep); werr != nil {
		return werr
	}

	lw.Writer.Flush()
	return nil
}

func (lw *LDIFWriter) writeDN(DN string) (err error) {
	// TODO need canonical DN?
	if len(DN) == 0 {
		return NewLDAPError(ErrorLDIFWrite, "DN has zero length.")
	}
	if err := lw.writeAttrLine("dn", DN); err != nil {
		return err
	}
	return
}

func (lw *LDIFWriter) writeEntry(e *Entry) error {
	for _, attr := range e.Attributes {
		for _, val := range attr.Values {
			if lw.EncAsBinary(attr.Name) || NeedsBase64Encoding(val) {
				if err := lw.writeEncAttr(attr.Name, val); err != nil {
					return err
				}
			} else {
				if err := lw.writeAttrLine(attr.Name, val); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (lw *LDIFWriter) writeEncAttr(attrName, val string) error {
	_, werr := lw.Writer.WriteString(attrName + ldifSep + ldifSep + " ")
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(toBase64(val))
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(lineSep)
	if werr != nil {
		return werr
	}
	return nil
}

func NeedsBase64Encoding(val string) bool {
	// zero len
	if len(val) == 0 {
		return false
	}
	// starts with a space, a colon, or a less than
	if val[0] == ' ' || val[0] == ':' || val[0] == '<' {
		return true
	}
	// final char is a space.
	if len(val) > 1 && strings.HasSuffix(val, " ") {
		return true
	}

	sl := len(val)
	for i := 0; i < sl; i++ {
		// outside ascii
		if val[i] > 127 || val[i] < 0 {
			return true
		}
		switch val[i] {
		case 0, 10, 14: // null, new line, carriage return
			return true
		}
	}
	return false
}

func (lw *LDIFWriter) writeMods(mods []Mod) error {
	for _, mod := range mods {
		if err := lw.writeAttrLine(ModMap[mod.ModOperation], mod.Modification.Name); err != nil {
			return err
		}
		for _, val := range mod.Modification.Values {
			if err := lw.writeAttrLine(mod.Modification.Name, val); err != nil {
				return err
			}
		}
		_, werr := lw.Writer.WriteString("-\n")
		if werr != nil {
			return werr
		}
	}
	return nil
}

func (lw *LDIFWriter) writeAttrLine(attrName, value string) error {
	_, werr := lw.Writer.WriteString(attrName)
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(ldifSep)
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(" ")
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(value)
	if werr != nil {
		return werr
	}
	_, werr = lw.Writer.WriteString(lineSep)
	if werr != nil {
		return werr
	}
	return nil
}

func toBase64(data string) string {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(data))
	encoder.Close()
	return buf.String()
}

func IsBinary(attrName string) (isBinary bool) {
	if strings.Contains(strings.ToLower(attrName), ";binary") {
		return true
	}
	if strings.Contains(strings.ToLower(attrName), "jpegphoto") {
		return true
	}
	return
}
