// build +coprocess

package main

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *AccessDefinition) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zcmr uint32
	zcmr, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zcmr > 0 {
		zcmr--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "api_name":
			z.APIName, err = dc.ReadString()
			if err != nil {
				return
			}
		case "api_id":
			z.APIID, err = dc.ReadString()
			if err != nil {
				return
			}
		case "versions":
			var zajw uint32
			zajw, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Versions) >= int(zajw) {
				z.Versions = z.Versions[:zajw]
			} else {
				z.Versions = make([]string, zajw)
			}
			for zxvk := range z.Versions {
				z.Versions[zxvk], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		case "allowed_urls":
			var zwht uint32
			zwht, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.AllowedURLs) >= int(zwht) {
				z.AllowedURLs = z.AllowedURLs[:zwht]
			} else {
				z.AllowedURLs = make([]AccessSpec, zwht)
			}
			for zbzg := range z.AllowedURLs {
				var zhct uint32
				zhct, err = dc.ReadMapHeader()
				if err != nil {
					return
				}
				for zhct > 0 {
					zhct--
					field, err = dc.ReadMapKeyPtr()
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "url":
						z.AllowedURLs[zbzg].URL, err = dc.ReadString()
						if err != nil {
							return
						}
					case "methods":
						var zcua uint32
						zcua, err = dc.ReadArrayHeader()
						if err != nil {
							return
						}
						if cap(z.AllowedURLs[zbzg].Methods) >= int(zcua) {
							z.AllowedURLs[zbzg].Methods = z.AllowedURLs[zbzg].Methods[:zcua]
						} else {
							z.AllowedURLs[zbzg].Methods = make([]string, zcua)
						}
						for zbai := range z.AllowedURLs[zbzg].Methods {
							z.AllowedURLs[zbzg].Methods[zbai], err = dc.ReadString()
							if err != nil {
								return
							}
						}
					default:
						err = dc.Skip()
						if err != nil {
							return
						}
					}
				}
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *AccessDefinition) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 4
	// write "api_name"
	err = en.Append(0x84, 0xa8, 0x61, 0x70, 0x69, 0x5f, 0x6e, 0x61, 0x6d, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteString(z.APIName)
	if err != nil {
		return
	}
	// write "api_id"
	err = en.Append(0xa6, 0x61, 0x70, 0x69, 0x5f, 0x69, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteString(z.APIID)
	if err != nil {
		return
	}
	// write "versions"
	err = en.Append(0xa8, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Versions)))
	if err != nil {
		return
	}
	for zxvk := range z.Versions {
		err = en.WriteString(z.Versions[zxvk])
		if err != nil {
			return
		}
	}
	// write "allowed_urls"
	err = en.Append(0xac, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x5f, 0x75, 0x72, 0x6c, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.AllowedURLs)))
	if err != nil {
		return
	}
	for zbzg := range z.AllowedURLs {
		// map header, size 2
		// write "url"
		err = en.Append(0x82, 0xa3, 0x75, 0x72, 0x6c)
		if err != nil {
			return err
		}
		err = en.WriteString(z.AllowedURLs[zbzg].URL)
		if err != nil {
			return
		}
		// write "methods"
		err = en.Append(0xa7, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73)
		if err != nil {
			return err
		}
		err = en.WriteArrayHeader(uint32(len(z.AllowedURLs[zbzg].Methods)))
		if err != nil {
			return
		}
		for zbai := range z.AllowedURLs[zbzg].Methods {
			err = en.WriteString(z.AllowedURLs[zbzg].Methods[zbai])
			if err != nil {
				return
			}
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *AccessDefinition) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 4
	// string "api_name"
	o = append(o, 0x84, 0xa8, 0x61, 0x70, 0x69, 0x5f, 0x6e, 0x61, 0x6d, 0x65)
	o = msgp.AppendString(o, z.APIName)
	// string "api_id"
	o = append(o, 0xa6, 0x61, 0x70, 0x69, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.APIID)
	// string "versions"
	o = append(o, 0xa8, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Versions)))
	for zxvk := range z.Versions {
		o = msgp.AppendString(o, z.Versions[zxvk])
	}
	// string "allowed_urls"
	o = append(o, 0xac, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x5f, 0x75, 0x72, 0x6c, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.AllowedURLs)))
	for zbzg := range z.AllowedURLs {
		// map header, size 2
		// string "url"
		o = append(o, 0x82, 0xa3, 0x75, 0x72, 0x6c)
		o = msgp.AppendString(o, z.AllowedURLs[zbzg].URL)
		// string "methods"
		o = append(o, 0xa7, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73)
		o = msgp.AppendArrayHeader(o, uint32(len(z.AllowedURLs[zbzg].Methods)))
		for zbai := range z.AllowedURLs[zbzg].Methods {
			o = msgp.AppendString(o, z.AllowedURLs[zbzg].Methods[zbai])
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AccessDefinition) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zxhx uint32
	zxhx, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zxhx > 0 {
		zxhx--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "api_name":
			z.APIName, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "api_id":
			z.APIID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "versions":
			var zlqf uint32
			zlqf, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Versions) >= int(zlqf) {
				z.Versions = z.Versions[:zlqf]
			} else {
				z.Versions = make([]string, zlqf)
			}
			for zxvk := range z.Versions {
				z.Versions[zxvk], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "allowed_urls":
			var zdaf uint32
			zdaf, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.AllowedURLs) >= int(zdaf) {
				z.AllowedURLs = z.AllowedURLs[:zdaf]
			} else {
				z.AllowedURLs = make([]AccessSpec, zdaf)
			}
			for zbzg := range z.AllowedURLs {
				var zpks uint32
				zpks, bts, err = msgp.ReadMapHeaderBytes(bts)
				if err != nil {
					return
				}
				for zpks > 0 {
					zpks--
					field, bts, err = msgp.ReadMapKeyZC(bts)
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "url":
						z.AllowedURLs[zbzg].URL, bts, err = msgp.ReadStringBytes(bts)
						if err != nil {
							return
						}
					case "methods":
						var zjfb uint32
						zjfb, bts, err = msgp.ReadArrayHeaderBytes(bts)
						if err != nil {
							return
						}
						if cap(z.AllowedURLs[zbzg].Methods) >= int(zjfb) {
							z.AllowedURLs[zbzg].Methods = z.AllowedURLs[zbzg].Methods[:zjfb]
						} else {
							z.AllowedURLs[zbzg].Methods = make([]string, zjfb)
						}
						for zbai := range z.AllowedURLs[zbzg].Methods {
							z.AllowedURLs[zbzg].Methods[zbai], bts, err = msgp.ReadStringBytes(bts)
							if err != nil {
								return
							}
						}
					default:
						bts, err = msgp.Skip(bts)
						if err != nil {
							return
						}
					}
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *AccessDefinition) Msgsize() (s int) {
	s = 1 + 9 + msgp.StringPrefixSize + len(z.APIName) + 7 + msgp.StringPrefixSize + len(z.APIID) + 9 + msgp.ArrayHeaderSize
	for zxvk := range z.Versions {
		s += msgp.StringPrefixSize + len(z.Versions[zxvk])
	}
	s += 13 + msgp.ArrayHeaderSize
	for zbzg := range z.AllowedURLs {
		s += 1 + 4 + msgp.StringPrefixSize + len(z.AllowedURLs[zbzg].URL) + 8 + msgp.ArrayHeaderSize
		for zbai := range z.AllowedURLs[zbzg].Methods {
			s += msgp.StringPrefixSize + len(z.AllowedURLs[zbzg].Methods[zbai])
		}
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *AccessSpec) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zeff uint32
	zeff, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zeff > 0 {
		zeff--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "url":
			z.URL, err = dc.ReadString()
			if err != nil {
				return
			}
		case "methods":
			var zrsw uint32
			zrsw, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Methods) >= int(zrsw) {
				z.Methods = z.Methods[:zrsw]
			} else {
				z.Methods = make([]string, zrsw)
			}
			for zcxo := range z.Methods {
				z.Methods[zcxo], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *AccessSpec) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "url"
	err = en.Append(0x82, 0xa3, 0x75, 0x72, 0x6c)
	if err != nil {
		return err
	}
	err = en.WriteString(z.URL)
	if err != nil {
		return
	}
	// write "methods"
	err = en.Append(0xa7, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Methods)))
	if err != nil {
		return
	}
	for zcxo := range z.Methods {
		err = en.WriteString(z.Methods[zcxo])
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *AccessSpec) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "url"
	o = append(o, 0x82, 0xa3, 0x75, 0x72, 0x6c)
	o = msgp.AppendString(o, z.URL)
	// string "methods"
	o = append(o, 0xa7, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Methods)))
	for zcxo := range z.Methods {
		o = msgp.AppendString(o, z.Methods[zcxo])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AccessSpec) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zxpk uint32
	zxpk, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zxpk > 0 {
		zxpk--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "url":
			z.URL, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "methods":
			var zdnj uint32
			zdnj, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Methods) >= int(zdnj) {
				z.Methods = z.Methods[:zdnj]
			} else {
				z.Methods = make([]string, zdnj)
			}
			for zcxo := range z.Methods {
				z.Methods[zcxo], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *AccessSpec) Msgsize() (s int) {
	s = 1 + 4 + msgp.StringPrefixSize + len(z.URL) + 8 + msgp.ArrayHeaderSize
	for zcxo := range z.Methods {
		s += msgp.StringPrefixSize + len(z.Methods[zcxo])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *HashType) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zobc string
		zobc, err = dc.ReadString()
		(*z) = HashType(zobc)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z HashType) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteString(string(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z HashType) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendString(o, string(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *HashType) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zsnv string
		zsnv, bts, err = msgp.ReadStringBytes(bts)
		(*z) = HashType(zsnv)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z HashType) Msgsize() (s int) {
	s = msgp.StringPrefixSize + len(string(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *SessionState) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zywj uint32
	zywj, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zywj > 0 {
		zywj--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "last_check":
			z.LastCheck, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "allowance":
			z.Allowance, err = dc.ReadFloat64()
			if err != nil {
				return
			}
		case "rate":
			z.Rate, err = dc.ReadFloat64()
			if err != nil {
				return
			}
		case "per":
			z.Per, err = dc.ReadFloat64()
			if err != nil {
				return
			}
		case "expires":
			z.Expires, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "quota_max":
			z.QuotaMax, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "quota_renews":
			z.QuotaRenews, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "quota_remaining":
			z.QuotaRemaining, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "quota_renewal_rate":
			z.QuotaRenewalRate, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "access_rights":
			var zjpj uint32
			zjpj, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.AccessRights == nil && zjpj > 0 {
				z.AccessRights = make(map[string]AccessDefinition, zjpj)
			} else if len(z.AccessRights) > 0 {
				for key, _ := range z.AccessRights {
					delete(z.AccessRights, key)
				}
			}
			for zjpj > 0 {
				zjpj--
				var zkgt string
				var zema AccessDefinition
				zkgt, err = dc.ReadString()
				if err != nil {
					return
				}
				err = zema.DecodeMsg(dc)
				if err != nil {
					return
				}
				z.AccessRights[zkgt] = zema
			}
		case "org_id":
			z.OrgID, err = dc.ReadString()
			if err != nil {
				return
			}
		case "oauth_client_id":
			z.OauthClientID, err = dc.ReadString()
			if err != nil {
				return
			}
		case "oauth_keys":
			var zzpf uint32
			zzpf, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.OauthKeys == nil && zzpf > 0 {
				z.OauthKeys = make(map[string]string, zzpf)
			} else if len(z.OauthKeys) > 0 {
				for key, _ := range z.OauthKeys {
					delete(z.OauthKeys, key)
				}
			}
			for zzpf > 0 {
				zzpf--
				var zpez string
				var zqke string
				zpez, err = dc.ReadString()
				if err != nil {
					return
				}
				zqke, err = dc.ReadString()
				if err != nil {
					return
				}
				z.OauthKeys[zpez] = zqke
			}
		case "basic_auth_data":
			var zrfe uint32
			zrfe, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			for zrfe > 0 {
				zrfe--
				field, err = dc.ReadMapKeyPtr()
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "password":
					z.BasicAuthData.Password, err = dc.ReadString()
					if err != nil {
						return
					}
				case "hash_type":
					{
						var zgmo string
						zgmo, err = dc.ReadString()
						z.BasicAuthData.Hash = HashType(zgmo)
					}
					if err != nil {
						return
					}
				default:
					err = dc.Skip()
					if err != nil {
						return
					}
				}
			}
		case "jwt_data":
			var ztaf uint32
			ztaf, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			for ztaf > 0 {
				ztaf--
				field, err = dc.ReadMapKeyPtr()
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "secret":
					z.JWTData.Secret, err = dc.ReadString()
					if err != nil {
						return
					}
				default:
					err = dc.Skip()
					if err != nil {
						return
					}
				}
			}
		case "hmac_enabled":
			z.HMACEnabled, err = dc.ReadBool()
			if err != nil {
				return
			}
		case "hmac_string":
			z.HmacSecret, err = dc.ReadString()
			if err != nil {
				return
			}
		case "is_inactive":
			z.IsInactive, err = dc.ReadBool()
			if err != nil {
				return
			}
		case "apply_policy_id":
			z.ApplyPolicyID, err = dc.ReadString()
			if err != nil {
				return
			}
		case "data_expires":
			z.DataExpires, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "monitor":
			var zeth uint32
			zeth, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			for zeth > 0 {
				zeth--
				field, err = dc.ReadMapKeyPtr()
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "trigger_limits":
					var zsbz uint32
					zsbz, err = dc.ReadArrayHeader()
					if err != nil {
						return
					}
					if cap(z.Monitor.TriggerLimits) >= int(zsbz) {
						z.Monitor.TriggerLimits = z.Monitor.TriggerLimits[:zsbz]
					} else {
						z.Monitor.TriggerLimits = make([]float64, zsbz)
					}
					for zqyh := range z.Monitor.TriggerLimits {
						z.Monitor.TriggerLimits[zqyh], err = dc.ReadFloat64()
						if err != nil {
							return
						}
					}
				default:
					err = dc.Skip()
					if err != nil {
						return
					}
				}
			}
		case "enable_detail_recording":
			z.EnableDetailedRecording, err = dc.ReadBool()
			if err != nil {
				return
			}
		case "meta_data":
			z.MetaData, err = dc.ReadIntf()
			if err != nil {
				return
			}
		case "tags":
			var zrjx uint32
			zrjx, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Tags) >= int(zrjx) {
				z.Tags = z.Tags[:zrjx]
			} else {
				z.Tags = make([]string, zrjx)
			}
			for zyzr := range z.Tags {
				z.Tags[zyzr], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		case "alias":
			z.Alias, err = dc.ReadString()
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *SessionState) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 25
	// write "last_check"
	err = en.Append(0xde, 0x0, 0x19, 0xaa, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.LastCheck)
	if err != nil {
		return
	}
	// write "allowance"
	err = en.Append(0xa9, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x61, 0x6e, 0x63, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteFloat64(z.Allowance)
	if err != nil {
		return
	}
	// write "rate"
	err = en.Append(0xa4, 0x72, 0x61, 0x74, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteFloat64(z.Rate)
	if err != nil {
		return
	}
	// write "per"
	err = en.Append(0xa3, 0x70, 0x65, 0x72)
	if err != nil {
		return err
	}
	err = en.WriteFloat64(z.Per)
	if err != nil {
		return
	}
	// write "expires"
	err = en.Append(0xa7, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.Expires)
	if err != nil {
		return
	}
	// write "quota_max"
	err = en.Append(0xa9, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x6d, 0x61, 0x78)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.QuotaMax)
	if err != nil {
		return
	}
	// write "quota_renews"
	err = en.Append(0xac, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6e, 0x65, 0x77, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.QuotaRenews)
	if err != nil {
		return
	}
	// write "quota_remaining"
	err = en.Append(0xaf, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.QuotaRemaining)
	if err != nil {
		return
	}
	// write "quota_renewal_rate"
	err = en.Append(0xb2, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6e, 0x65, 0x77, 0x61, 0x6c, 0x5f, 0x72, 0x61, 0x74, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.QuotaRenewalRate)
	if err != nil {
		return
	}
	// write "access_rights"
	err = en.Append(0xad, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x69, 0x67, 0x68, 0x74, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.AccessRights)))
	if err != nil {
		return
	}
	for zkgt, zema := range z.AccessRights {
		err = en.WriteString(zkgt)
		if err != nil {
			return
		}
		err = zema.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "org_id"
	err = en.Append(0xa6, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteString(z.OrgID)
	if err != nil {
		return
	}
	// write "oauth_client_id"
	err = en.Append(0xaf, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteString(z.OauthClientID)
	if err != nil {
		return
	}
	// write "oauth_keys"
	err = en.Append(0xaa, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.OauthKeys)))
	if err != nil {
		return
	}
	for zpez, zqke := range z.OauthKeys {
		err = en.WriteString(zpez)
		if err != nil {
			return
		}
		err = en.WriteString(zqke)
		if err != nil {
			return
		}
	}
	// write "basic_auth_data"
	// map header, size 2
	// write "password"
	err = en.Append(0xaf, 0x62, 0x61, 0x73, 0x69, 0x63, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x82, 0xa8, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteString(z.BasicAuthData.Password)
	if err != nil {
		return
	}
	// write "hash_type"
	err = en.Append(0xa9, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x74, 0x79, 0x70, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteString(string(z.BasicAuthData.Hash))
	if err != nil {
		return
	}
	// write "jwt_data"
	// map header, size 1
	// write "secret"
	err = en.Append(0xa8, 0x6a, 0x77, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x81, 0xa6, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteString(z.JWTData.Secret)
	if err != nil {
		return
	}
	// write "hmac_enabled"
	err = en.Append(0xac, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteBool(z.HMACEnabled)
	if err != nil {
		return
	}
	// write "hmac_string"
	err = en.Append(0xab, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteString(z.HmacSecret)
	if err != nil {
		return
	}
	// write "is_inactive"
	err = en.Append(0xab, 0x69, 0x73, 0x5f, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBool(z.IsInactive)
	if err != nil {
		return
	}
	// write "apply_policy_id"
	err = en.Append(0xaf, 0x61, 0x70, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x69, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteString(z.ApplyPolicyID)
	if err != nil {
		return
	}
	// write "data_expires"
	err = en.Append(0xac, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.DataExpires)
	if err != nil {
		return
	}
	// write "monitor"
	// map header, size 1
	// write "trigger_limits"
	err = en.Append(0xa7, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x81, 0xae, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Monitor.TriggerLimits)))
	if err != nil {
		return
	}
	for zqyh := range z.Monitor.TriggerLimits {
		err = en.WriteFloat64(z.Monitor.TriggerLimits[zqyh])
		if err != nil {
			return
		}
	}
	// write "enable_detail_recording"
	err = en.Append(0xb7, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteBool(z.EnableDetailedRecording)
	if err != nil {
		return
	}
	// write "meta_data"
	err = en.Append(0xa9, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x64, 0x61, 0x74, 0x61)
	if err != nil {
		return err
	}
	err = en.WriteIntf(z.MetaData)
	if err != nil {
		return
	}
	// write "tags"
	err = en.Append(0xa4, 0x74, 0x61, 0x67, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Tags)))
	if err != nil {
		return
	}
	for zyzr := range z.Tags {
		err = en.WriteString(z.Tags[zyzr])
		if err != nil {
			return
		}
	}
	// write "alias"
	err = en.Append(0xa5, 0x61, 0x6c, 0x69, 0x61, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteString(z.Alias)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *SessionState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 25
	// string "last_check"
	o = append(o, 0xde, 0x0, 0x19, 0xaa, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b)
	o = msgp.AppendInt64(o, z.LastCheck)
	// string "allowance"
	o = append(o, 0xa9, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x61, 0x6e, 0x63, 0x65)
	o = msgp.AppendFloat64(o, z.Allowance)
	// string "rate"
	o = append(o, 0xa4, 0x72, 0x61, 0x74, 0x65)
	o = msgp.AppendFloat64(o, z.Rate)
	// string "per"
	o = append(o, 0xa3, 0x70, 0x65, 0x72)
	o = msgp.AppendFloat64(o, z.Per)
	// string "expires"
	o = append(o, 0xa7, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73)
	o = msgp.AppendInt64(o, z.Expires)
	// string "quota_max"
	o = append(o, 0xa9, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x6d, 0x61, 0x78)
	o = msgp.AppendInt64(o, z.QuotaMax)
	// string "quota_renews"
	o = append(o, 0xac, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6e, 0x65, 0x77, 0x73)
	o = msgp.AppendInt64(o, z.QuotaRenews)
	// string "quota_remaining"
	o = append(o, 0xaf, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67)
	o = msgp.AppendInt64(o, z.QuotaRemaining)
	// string "quota_renewal_rate"
	o = append(o, 0xb2, 0x71, 0x75, 0x6f, 0x74, 0x61, 0x5f, 0x72, 0x65, 0x6e, 0x65, 0x77, 0x61, 0x6c, 0x5f, 0x72, 0x61, 0x74, 0x65)
	o = msgp.AppendInt64(o, z.QuotaRenewalRate)
	// string "access_rights"
	o = append(o, 0xad, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x69, 0x67, 0x68, 0x74, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.AccessRights)))
	for zkgt, zema := range z.AccessRights {
		o = msgp.AppendString(o, zkgt)
		o, err = zema.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "org_id"
	o = append(o, 0xa6, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.OrgID)
	// string "oauth_client_id"
	o = append(o, 0xaf, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.OauthClientID)
	// string "oauth_keys"
	o = append(o, 0xaa, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.OauthKeys)))
	for zpez, zqke := range z.OauthKeys {
		o = msgp.AppendString(o, zpez)
		o = msgp.AppendString(o, zqke)
	}
	// string "basic_auth_data"
	// map header, size 2
	// string "password"
	o = append(o, 0xaf, 0x62, 0x61, 0x73, 0x69, 0x63, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x82, 0xa8, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64)
	o = msgp.AppendString(o, z.BasicAuthData.Password)
	// string "hash_type"
	o = append(o, 0xa9, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x74, 0x79, 0x70, 0x65)
	o = msgp.AppendString(o, string(z.BasicAuthData.Hash))
	// string "jwt_data"
	// map header, size 1
	// string "secret"
	o = append(o, 0xa8, 0x6a, 0x77, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x81, 0xa6, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74)
	o = msgp.AppendString(o, z.JWTData.Secret)
	// string "hmac_enabled"
	o = append(o, 0xac, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64)
	o = msgp.AppendBool(o, z.HMACEnabled)
	// string "hmac_string"
	o = append(o, 0xab, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67)
	o = msgp.AppendString(o, z.HmacSecret)
	// string "is_inactive"
	o = append(o, 0xab, 0x69, 0x73, 0x5f, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65)
	o = msgp.AppendBool(o, z.IsInactive)
	// string "apply_policy_id"
	o = append(o, 0xaf, 0x61, 0x70, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.ApplyPolicyID)
	// string "data_expires"
	o = append(o, 0xac, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73)
	o = msgp.AppendInt64(o, z.DataExpires)
	// string "monitor"
	// map header, size 1
	// string "trigger_limits"
	o = append(o, 0xa7, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x81, 0xae, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Monitor.TriggerLimits)))
	for zqyh := range z.Monitor.TriggerLimits {
		o = msgp.AppendFloat64(o, z.Monitor.TriggerLimits[zqyh])
	}
	// string "enable_detail_recording"
	o = append(o, 0xb7, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67)
	o = msgp.AppendBool(o, z.EnableDetailedRecording)
	// string "meta_data"
	o = append(o, 0xa9, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x64, 0x61, 0x74, 0x61)
	o, err = msgp.AppendIntf(o, z.MetaData)
	if err != nil {
		return
	}
	// string "tags"
	o = append(o, 0xa4, 0x74, 0x61, 0x67, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Tags)))
	for zyzr := range z.Tags {
		o = msgp.AppendString(o, z.Tags[zyzr])
	}
	// string "alias"
	o = append(o, 0xa5, 0x61, 0x6c, 0x69, 0x61, 0x73)
	o = msgp.AppendString(o, z.Alias)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *SessionState) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zawn uint32
	zawn, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zawn > 0 {
		zawn--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "last_check":
			z.LastCheck, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "allowance":
			z.Allowance, bts, err = msgp.ReadFloat64Bytes(bts)
			if err != nil {
				return
			}
		case "rate":
			z.Rate, bts, err = msgp.ReadFloat64Bytes(bts)
			if err != nil {
				return
			}
		case "per":
			z.Per, bts, err = msgp.ReadFloat64Bytes(bts)
			if err != nil {
				return
			}
		case "expires":
			z.Expires, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "quota_max":
			z.QuotaMax, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "quota_renews":
			z.QuotaRenews, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "quota_remaining":
			z.QuotaRemaining, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "quota_renewal_rate":
			z.QuotaRenewalRate, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "access_rights":
			var zwel uint32
			zwel, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.AccessRights == nil && zwel > 0 {
				z.AccessRights = make(map[string]AccessDefinition, zwel)
			} else if len(z.AccessRights) > 0 {
				for key, _ := range z.AccessRights {
					delete(z.AccessRights, key)
				}
			}
			for zwel > 0 {
				var zkgt string
				var zema AccessDefinition
				zwel--
				zkgt, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				bts, err = zema.UnmarshalMsg(bts)
				if err != nil {
					return
				}
				z.AccessRights[zkgt] = zema
			}
		case "org_id":
			z.OrgID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "oauth_client_id":
			z.OauthClientID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "oauth_keys":
			var zrbe uint32
			zrbe, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.OauthKeys == nil && zrbe > 0 {
				z.OauthKeys = make(map[string]string, zrbe)
			} else if len(z.OauthKeys) > 0 {
				for key, _ := range z.OauthKeys {
					delete(z.OauthKeys, key)
				}
			}
			for zrbe > 0 {
				var zpez string
				var zqke string
				zrbe--
				zpez, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				zqke, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				z.OauthKeys[zpez] = zqke
			}
		case "basic_auth_data":
			var zmfd uint32
			zmfd, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			for zmfd > 0 {
				zmfd--
				field, bts, err = msgp.ReadMapKeyZC(bts)
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "password":
					z.BasicAuthData.Password, bts, err = msgp.ReadStringBytes(bts)
					if err != nil {
						return
					}
				case "hash_type":
					{
						var zzdc string
						zzdc, bts, err = msgp.ReadStringBytes(bts)
						z.BasicAuthData.Hash = HashType(zzdc)
					}
					if err != nil {
						return
					}
				default:
					bts, err = msgp.Skip(bts)
					if err != nil {
						return
					}
				}
			}
		case "jwt_data":
			var zelx uint32
			zelx, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			for zelx > 0 {
				zelx--
				field, bts, err = msgp.ReadMapKeyZC(bts)
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "secret":
					z.JWTData.Secret, bts, err = msgp.ReadStringBytes(bts)
					if err != nil {
						return
					}
				default:
					bts, err = msgp.Skip(bts)
					if err != nil {
						return
					}
				}
			}
		case "hmac_enabled":
			z.HMACEnabled, bts, err = msgp.ReadBoolBytes(bts)
			if err != nil {
				return
			}
		case "hmac_string":
			z.HmacSecret, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "is_inactive":
			z.IsInactive, bts, err = msgp.ReadBoolBytes(bts)
			if err != nil {
				return
			}
		case "apply_policy_id":
			z.ApplyPolicyID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "data_expires":
			z.DataExpires, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "monitor":
			var zbal uint32
			zbal, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			for zbal > 0 {
				zbal--
				field, bts, err = msgp.ReadMapKeyZC(bts)
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "trigger_limits":
					var zjqz uint32
					zjqz, bts, err = msgp.ReadArrayHeaderBytes(bts)
					if err != nil {
						return
					}
					if cap(z.Monitor.TriggerLimits) >= int(zjqz) {
						z.Monitor.TriggerLimits = z.Monitor.TriggerLimits[:zjqz]
					} else {
						z.Monitor.TriggerLimits = make([]float64, zjqz)
					}
					for zqyh := range z.Monitor.TriggerLimits {
						z.Monitor.TriggerLimits[zqyh], bts, err = msgp.ReadFloat64Bytes(bts)
						if err != nil {
							return
						}
					}
				default:
					bts, err = msgp.Skip(bts)
					if err != nil {
						return
					}
				}
			}
		case "enable_detail_recording":
			z.EnableDetailedRecording, bts, err = msgp.ReadBoolBytes(bts)
			if err != nil {
				return
			}
		case "meta_data":
			z.MetaData, bts, err = msgp.ReadIntfBytes(bts)
			if err != nil {
				return
			}
		case "tags":
			var zkct uint32
			zkct, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Tags) >= int(zkct) {
				z.Tags = z.Tags[:zkct]
			} else {
				z.Tags = make([]string, zkct)
			}
			for zyzr := range z.Tags {
				z.Tags[zyzr], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "alias":
			z.Alias, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *SessionState) Msgsize() (s int) {
	s = 3 + 11 + msgp.Int64Size + 10 + msgp.Float64Size + 5 + msgp.Float64Size + 4 + msgp.Float64Size + 8 + msgp.Int64Size + 10 + msgp.Int64Size + 13 + msgp.Int64Size + 16 + msgp.Int64Size + 19 + msgp.Int64Size + 14 + msgp.MapHeaderSize
	if z.AccessRights != nil {
		for zkgt, zema := range z.AccessRights {
			_ = zema
			s += msgp.StringPrefixSize + len(zkgt) + zema.Msgsize()
		}
	}
	s += 7 + msgp.StringPrefixSize + len(z.OrgID) + 16 + msgp.StringPrefixSize + len(z.OauthClientID) + 11 + msgp.MapHeaderSize
	if z.OauthKeys != nil {
		for zpez, zqke := range z.OauthKeys {
			_ = zqke
			s += msgp.StringPrefixSize + len(zpez) + msgp.StringPrefixSize + len(zqke)
		}
	}
	s += 16 + 1 + 9 + msgp.StringPrefixSize + len(z.BasicAuthData.Password) + 10 + msgp.StringPrefixSize + len(string(z.BasicAuthData.Hash)) + 9 + 1 + 7 + msgp.StringPrefixSize + len(z.JWTData.Secret) + 13 + msgp.BoolSize + 12 + msgp.StringPrefixSize + len(z.HmacSecret) + 12 + msgp.BoolSize + 16 + msgp.StringPrefixSize + len(z.ApplyPolicyID) + 13 + msgp.Int64Size + 8 + 1 + 15 + msgp.ArrayHeaderSize + (len(z.Monitor.TriggerLimits) * (msgp.Float64Size)) + 24 + msgp.BoolSize + 10 + msgp.GuessSize(z.MetaData) + 5 + msgp.ArrayHeaderSize
	for zyzr := range z.Tags {
		s += msgp.StringPrefixSize + len(z.Tags[zyzr])
	}
	s += 6 + msgp.StringPrefixSize + len(z.Alias)
	return
}
