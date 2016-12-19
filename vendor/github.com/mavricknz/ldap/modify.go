// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

const (
	ModAdd       = 0
	ModDelete    = 1
	ModReplace   = 2
	ModIncrement = 3
)

var ModMap map[uint8]string = map[uint8]string{
	ModAdd:       "add",
	ModDelete:    "delete",
	ModReplace:   "replace",
	ModIncrement: "increment",
}

/* Reuse search struct, should Values be a [][]byte
type EntryAttribute struct {
	Name   string
	Values []string
}
*/
type Mod struct {
	ModOperation uint8
	Modification EntryAttribute
}

type ModifyRequest struct {
	DN       string
	Mods     []Mod
	Controls []Control
}

func (req *ModifyRequest) RecordType() uint8 {
	return ModifyRecord
}

/* Example...
func modifyTest(l *ldap.Conn){
    var modDNs []string = []string{"cn=test,ou=People,dc=example,dc=com"}
    var modAttrs []string = []string{"cn"}
    var modValues []string = []string{"aaa", "bbb", "ccc"}
	modreq := ldap.NewModifyRequest(modDNs[0])
	mod := ldap.NewMod(ldap.ModAdd, modAttrs[0], modValues)
	modreq.AddMod(mod)
    err := l.Modify(modreq)
	if err != nil {
        fmt.Printf("Modify : %s : result = %d\n",modDNs[0],err.ResultCode)
        return
    }
    fmt.Printf("Modify Success")
}

   ModifyRequest ::= [APPLICATION 6] SEQUENCE {
         object          LDAPDN,
         changes         SEQUENCE OF change SEQUENCE {
              operation       ENUMERATED {
                   add     (0),
                   delete  (1),
                   replace (2),
                   ...  },
              modification    PartialAttribute } }
*/
func (l *LDAPConnection) Modify(modReq *ModifyRequest) error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "MessageID channel is closed.")
	}
	encodedModify := encodeModifyRequest(modReq)

	packet, err := requestBuildPacket(messageID, encodedModify, modReq.Controls)
	if err != nil {
		return err
	}

	return l.sendReqRespPacket(messageID, packet)
}

func (req *ModifyRequest) Bytes() []byte {
	return encodeModifyRequest(req).Bytes()
}

func encodeModifyRequest(req *ModifyRequest) (p *ber.Packet) {
	modpacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, ApplicationMap[ApplicationModifyRequest])
	modpacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.DN, "LDAP DN"))
	seqOfChanges := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for _, mod := range req.Mods {
		modification := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Modification")
		op := ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(mod.ModOperation), "Modify Op ("+ModMap[mod.ModOperation]+")")
		modification.AppendChild(op)
		partAttr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")

		partAttr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, mod.Modification.Name, "AttributeDescription"))
		valuesSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Value Set")
		for _, val := range mod.Modification.Values {
			value := ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, val, "AttributeValue")
			valuesSet.AppendChild(value)
		}
		partAttr.AppendChild(valuesSet)
		modification.AppendChild(partAttr)
		seqOfChanges.AppendChild(modification)
	}
	modpacket.AppendChild(seqOfChanges)

	return modpacket
}

func NewModifyRequest(dn string) (req *ModifyRequest) {
	req = &ModifyRequest{
		DN:       dn,
		Mods:     make([]Mod, 0),
		Controls: make([]Control, 0),
	}
	return
}

// Basic LDIF dump, no formating, etc
func (req *ModifyRequest) String() (dump string) {
	dump = fmt.Sprintf("dn: %s\n", req.DN)
	dump = fmt.Sprintf("changetype: modify\n")
	for _, mod := range req.Mods {
		dump += mod.DumpMod()
	}
	return
}

// Basic LDIF dump, no formating, etc
func (mod *Mod) DumpMod() (dump string) {
	dump += fmt.Sprintf("%s: %s\n", ModMap[mod.ModOperation], mod.Modification.Name)
	for _, val := range mod.Modification.Values {
		dump += fmt.Sprintf("%s: %s\n", mod.Modification.Name, val)
	}
	dump += "-\n"
	return dump
}

func NewMod(modType uint8, attr string, values []string) (mod *Mod) {
	if values == nil {
		values = []string{}
	}
	partEntryAttr := EntryAttribute{Name: attr, Values: values}
	mod = &Mod{ModOperation: modType, Modification: partEntryAttr}
	return
}

func (req *ModifyRequest) AddMod(mod *Mod) {
	req.Mods = append(req.Mods, *mod)
}

func (req *ModifyRequest) AddMods(mods []Mod) {
	req.Mods = append(req.Mods, mods...)
}

func (req *ModifyRequest) AddControl(control Control) {
	if req.Controls == nil {
		req.Controls = make([]Control, 0)
	}
	req.Controls = append(req.Controls, control)
}
