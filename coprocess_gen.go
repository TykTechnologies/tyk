// +build coprocess

package main

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"C"

	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *CoProcessMiniRequestObject) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zrsw uint32
	zrsw, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zrsw > 0 {
		zrsw--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "headers":
			var zxpk uint32
			zxpk, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.Headers == nil && zxpk > 0 {
				z.Headers = make(map[string][]string, zxpk)
			} else if len(z.Headers) > 0 {
				for key, _ := range z.Headers {
					delete(z.Headers, key)
				}
			}
			for zxpk > 0 {
				zxpk--
				var zxvk string
				var zbzg []string
				zxvk, err = dc.ReadString()
				if err != nil {
					return
				}
				var zdnj uint32
				zdnj, err = dc.ReadArrayHeader()
				if err != nil {
					return
				}
				if cap(zbzg) >= int(zdnj) {
					zbzg = zbzg[:zdnj]
				} else {
					zbzg = make([]string, zdnj)
				}
				for zbai := range zbzg {
					zbzg[zbai], err = dc.ReadString()
					if err != nil {
						return
					}
				}
				z.Headers[zxvk] = zbzg
			}
		case "set_headers":
			var zobc uint32
			zobc, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.SetHeaders == nil && zobc > 0 {
				z.SetHeaders = make(map[string]string, zobc)
			} else if len(z.SetHeaders) > 0 {
				for key, _ := range z.SetHeaders {
					delete(z.SetHeaders, key)
				}
			}
			for zobc > 0 {
				zobc--
				var zcmr string
				var zajw string
				zcmr, err = dc.ReadString()
				if err != nil {
					return
				}
				zajw, err = dc.ReadString()
				if err != nil {
					return
				}
				z.SetHeaders[zcmr] = zajw
			}
		case "delete_headers":
			var zsnv uint32
			zsnv, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.DeleteHeaders) >= int(zsnv) {
				z.DeleteHeaders = z.DeleteHeaders[:zsnv]
			} else {
				z.DeleteHeaders = make([]string, zsnv)
			}
			for zwht := range z.DeleteHeaders {
				z.DeleteHeaders[zwht], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		case "body":
			z.Body, err = dc.ReadString()
			if err != nil {
				return
			}
		case "url":
			z.URL, err = dc.ReadString()
			if err != nil {
				return
			}
		case "params":
			var zkgt uint32
			zkgt, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.Params == nil && zkgt > 0 {
				z.Params = make(map[string][]string, zkgt)
			} else if len(z.Params) > 0 {
				for key, _ := range z.Params {
					delete(z.Params, key)
				}
			}
			for zkgt > 0 {
				zkgt--
				var zhct string
				var zcua []string
				zhct, err = dc.ReadString()
				if err != nil {
					return
				}
				var zema uint32
				zema, err = dc.ReadArrayHeader()
				if err != nil {
					return
				}
				if cap(zcua) >= int(zema) {
					zcua = zcua[:zema]
				} else {
					zcua = make([]string, zema)
				}
				for zxhx := range zcua {
					zcua[zxhx], err = dc.ReadString()
					if err != nil {
						return
					}
				}
				z.Params[zhct] = zcua
			}
		case "add_params":
			var zpez uint32
			zpez, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.AddParams == nil && zpez > 0 {
				z.AddParams = make(map[string]string, zpez)
			} else if len(z.AddParams) > 0 {
				for key, _ := range z.AddParams {
					delete(z.AddParams, key)
				}
			}
			for zpez > 0 {
				zpez--
				var zlqf string
				var zdaf string
				zlqf, err = dc.ReadString()
				if err != nil {
					return
				}
				zdaf, err = dc.ReadString()
				if err != nil {
					return
				}
				z.AddParams[zlqf] = zdaf
			}
		case "extended_params":
			var zqke uint32
			zqke, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.ExtendedParams == nil && zqke > 0 {
				z.ExtendedParams = make(map[string][]string, zqke)
			} else if len(z.ExtendedParams) > 0 {
				for key, _ := range z.ExtendedParams {
					delete(z.ExtendedParams, key)
				}
			}
			for zqke > 0 {
				zqke--
				var zpks string
				var zjfb []string
				zpks, err = dc.ReadString()
				if err != nil {
					return
				}
				var zqyh uint32
				zqyh, err = dc.ReadArrayHeader()
				if err != nil {
					return
				}
				if cap(zjfb) >= int(zqyh) {
					zjfb = zjfb[:zqyh]
				} else {
					zjfb = make([]string, zqyh)
				}
				for zcxo := range zjfb {
					zjfb[zcxo], err = dc.ReadString()
					if err != nil {
						return
					}
				}
				z.ExtendedParams[zpks] = zjfb
			}
		case "delete_params":
			var zyzr uint32
			zyzr, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.DeleteParams) >= int(zyzr) {
				z.DeleteParams = z.DeleteParams[:zyzr]
			} else {
				z.DeleteParams = make([]string, zyzr)
			}
			for zeff := range z.DeleteParams {
				z.DeleteParams[zeff], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		case "return_overrides":
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
				case "response_code":
					z.ReturnOverrides.ResponseCode, err = dc.ReadInt()
					if err != nil {
						return
					}
				case "response_error":
					z.ReturnOverrides.ResponseError, err = dc.ReadString()
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
func (z *CoProcessMiniRequestObject) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 10
	// write "headers"
	err = en.Append(0x8a, 0xa7, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.Headers)))
	if err != nil {
		return
	}
	for zxvk, zbzg := range z.Headers {
		err = en.WriteString(zxvk)
		if err != nil {
			return
		}
		err = en.WriteArrayHeader(uint32(len(zbzg)))
		if err != nil {
			return
		}
		for zbai := range zbzg {
			err = en.WriteString(zbzg[zbai])
			if err != nil {
				return
			}
		}
	}
	// write "set_headers"
	err = en.Append(0xab, 0x73, 0x65, 0x74, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.SetHeaders)))
	if err != nil {
		return
	}
	for zcmr, zajw := range z.SetHeaders {
		err = en.WriteString(zcmr)
		if err != nil {
			return
		}
		err = en.WriteString(zajw)
		if err != nil {
			return
		}
	}
	// write "delete_headers"
	err = en.Append(0xae, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.DeleteHeaders)))
	if err != nil {
		return
	}
	for zwht := range z.DeleteHeaders {
		err = en.WriteString(z.DeleteHeaders[zwht])
		if err != nil {
			return
		}
	}
	// write "body"
	err = en.Append(0xa4, 0x62, 0x6f, 0x64, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteString(z.Body)
	if err != nil {
		return
	}
	// write "url"
	err = en.Append(0xa3, 0x75, 0x72, 0x6c)
	if err != nil {
		return err
	}
	err = en.WriteString(z.URL)
	if err != nil {
		return
	}
	// write "params"
	err = en.Append(0xa6, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.Params)))
	if err != nil {
		return
	}
	for zhct, zcua := range z.Params {
		err = en.WriteString(zhct)
		if err != nil {
			return
		}
		err = en.WriteArrayHeader(uint32(len(zcua)))
		if err != nil {
			return
		}
		for zxhx := range zcua {
			err = en.WriteString(zcua[zxhx])
			if err != nil {
				return
			}
		}
	}
	// write "add_params"
	err = en.Append(0xaa, 0x61, 0x64, 0x64, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.AddParams)))
	if err != nil {
		return
	}
	for zlqf, zdaf := range z.AddParams {
		err = en.WriteString(zlqf)
		if err != nil {
			return
		}
		err = en.WriteString(zdaf)
		if err != nil {
			return
		}
	}
	// write "extended_params"
	err = en.Append(0xaf, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.ExtendedParams)))
	if err != nil {
		return
	}
	for zpks, zjfb := range z.ExtendedParams {
		err = en.WriteString(zpks)
		if err != nil {
			return
		}
		err = en.WriteArrayHeader(uint32(len(zjfb)))
		if err != nil {
			return
		}
		for zcxo := range zjfb {
			err = en.WriteString(zjfb[zcxo])
			if err != nil {
				return
			}
		}
	}
	// write "delete_params"
	err = en.Append(0xad, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.DeleteParams)))
	if err != nil {
		return
	}
	for zeff := range z.DeleteParams {
		err = en.WriteString(z.DeleteParams[zeff])
		if err != nil {
			return
		}
	}
	// write "return_overrides"
	// map header, size 2
	// write "response_code"
	err = en.Append(0xb0, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x73, 0x82, 0xad, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteInt(z.ReturnOverrides.ResponseCode)
	if err != nil {
		return
	}
	// write "response_error"
	err = en.Append(0xae, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72)
	if err != nil {
		return err
	}
	err = en.WriteString(z.ReturnOverrides.ResponseError)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *CoProcessMiniRequestObject) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 10
	// string "headers"
	o = append(o, 0x8a, 0xa7, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.Headers)))
	for zxvk, zbzg := range z.Headers {
		o = msgp.AppendString(o, zxvk)
		o = msgp.AppendArrayHeader(o, uint32(len(zbzg)))
		for zbai := range zbzg {
			o = msgp.AppendString(o, zbzg[zbai])
		}
	}
	// string "set_headers"
	o = append(o, 0xab, 0x73, 0x65, 0x74, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.SetHeaders)))
	for zcmr, zajw := range z.SetHeaders {
		o = msgp.AppendString(o, zcmr)
		o = msgp.AppendString(o, zajw)
	}
	// string "delete_headers"
	o = append(o, 0xae, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.DeleteHeaders)))
	for zwht := range z.DeleteHeaders {
		o = msgp.AppendString(o, z.DeleteHeaders[zwht])
	}
	// string "body"
	o = append(o, 0xa4, 0x62, 0x6f, 0x64, 0x79)
	o = msgp.AppendString(o, z.Body)
	// string "url"
	o = append(o, 0xa3, 0x75, 0x72, 0x6c)
	o = msgp.AppendString(o, z.URL)
	// string "params"
	o = append(o, 0xa6, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.Params)))
	for zhct, zcua := range z.Params {
		o = msgp.AppendString(o, zhct)
		o = msgp.AppendArrayHeader(o, uint32(len(zcua)))
		for zxhx := range zcua {
			o = msgp.AppendString(o, zcua[zxhx])
		}
	}
	// string "add_params"
	o = append(o, 0xaa, 0x61, 0x64, 0x64, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.AddParams)))
	for zlqf, zdaf := range z.AddParams {
		o = msgp.AppendString(o, zlqf)
		o = msgp.AppendString(o, zdaf)
	}
	// string "extended_params"
	o = append(o, 0xaf, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.ExtendedParams)))
	for zpks, zjfb := range z.ExtendedParams {
		o = msgp.AppendString(o, zpks)
		o = msgp.AppendArrayHeader(o, uint32(len(zjfb)))
		for zcxo := range zjfb {
			o = msgp.AppendString(o, zjfb[zcxo])
		}
	}
	// string "delete_params"
	o = append(o, 0xad, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.DeleteParams)))
	for zeff := range z.DeleteParams {
		o = msgp.AppendString(o, z.DeleteParams[zeff])
	}
	// string "return_overrides"
	// map header, size 2
	// string "response_code"
	o = append(o, 0xb0, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x73, 0x82, 0xad, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	o = msgp.AppendInt(o, z.ReturnOverrides.ResponseCode)
	// string "response_error"
	o = append(o, 0xae, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72)
	o = msgp.AppendString(o, z.ReturnOverrides.ResponseError)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *CoProcessMiniRequestObject) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zjpj uint32
	zjpj, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zjpj > 0 {
		zjpj--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "headers":
			var zzpf uint32
			zzpf, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.Headers == nil && zzpf > 0 {
				z.Headers = make(map[string][]string, zzpf)
			} else if len(z.Headers) > 0 {
				for key, _ := range z.Headers {
					delete(z.Headers, key)
				}
			}
			for zzpf > 0 {
				var zxvk string
				var zbzg []string
				zzpf--
				zxvk, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				var zrfe uint32
				zrfe, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					return
				}
				if cap(zbzg) >= int(zrfe) {
					zbzg = zbzg[:zrfe]
				} else {
					zbzg = make([]string, zrfe)
				}
				for zbai := range zbzg {
					zbzg[zbai], bts, err = msgp.ReadStringBytes(bts)
					if err != nil {
						return
					}
				}
				z.Headers[zxvk] = zbzg
			}
		case "set_headers":
			var zgmo uint32
			zgmo, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.SetHeaders == nil && zgmo > 0 {
				z.SetHeaders = make(map[string]string, zgmo)
			} else if len(z.SetHeaders) > 0 {
				for key, _ := range z.SetHeaders {
					delete(z.SetHeaders, key)
				}
			}
			for zgmo > 0 {
				var zcmr string
				var zajw string
				zgmo--
				zcmr, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				zajw, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				z.SetHeaders[zcmr] = zajw
			}
		case "delete_headers":
			var ztaf uint32
			ztaf, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.DeleteHeaders) >= int(ztaf) {
				z.DeleteHeaders = z.DeleteHeaders[:ztaf]
			} else {
				z.DeleteHeaders = make([]string, ztaf)
			}
			for zwht := range z.DeleteHeaders {
				z.DeleteHeaders[zwht], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "body":
			z.Body, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "url":
			z.URL, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "params":
			var zeth uint32
			zeth, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.Params == nil && zeth > 0 {
				z.Params = make(map[string][]string, zeth)
			} else if len(z.Params) > 0 {
				for key, _ := range z.Params {
					delete(z.Params, key)
				}
			}
			for zeth > 0 {
				var zhct string
				var zcua []string
				zeth--
				zhct, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				var zsbz uint32
				zsbz, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					return
				}
				if cap(zcua) >= int(zsbz) {
					zcua = zcua[:zsbz]
				} else {
					zcua = make([]string, zsbz)
				}
				for zxhx := range zcua {
					zcua[zxhx], bts, err = msgp.ReadStringBytes(bts)
					if err != nil {
						return
					}
				}
				z.Params[zhct] = zcua
			}
		case "add_params":
			var zrjx uint32
			zrjx, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.AddParams == nil && zrjx > 0 {
				z.AddParams = make(map[string]string, zrjx)
			} else if len(z.AddParams) > 0 {
				for key, _ := range z.AddParams {
					delete(z.AddParams, key)
				}
			}
			for zrjx > 0 {
				var zlqf string
				var zdaf string
				zrjx--
				zlqf, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				zdaf, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				z.AddParams[zlqf] = zdaf
			}
		case "extended_params":
			var zawn uint32
			zawn, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.ExtendedParams == nil && zawn > 0 {
				z.ExtendedParams = make(map[string][]string, zawn)
			} else if len(z.ExtendedParams) > 0 {
				for key, _ := range z.ExtendedParams {
					delete(z.ExtendedParams, key)
				}
			}
			for zawn > 0 {
				var zpks string
				var zjfb []string
				zawn--
				zpks, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				var zwel uint32
				zwel, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					return
				}
				if cap(zjfb) >= int(zwel) {
					zjfb = zjfb[:zwel]
				} else {
					zjfb = make([]string, zwel)
				}
				for zcxo := range zjfb {
					zjfb[zcxo], bts, err = msgp.ReadStringBytes(bts)
					if err != nil {
						return
					}
				}
				z.ExtendedParams[zpks] = zjfb
			}
		case "delete_params":
			var zrbe uint32
			zrbe, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.DeleteParams) >= int(zrbe) {
				z.DeleteParams = z.DeleteParams[:zrbe]
			} else {
				z.DeleteParams = make([]string, zrbe)
			}
			for zeff := range z.DeleteParams {
				z.DeleteParams[zeff], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "return_overrides":
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
				case "response_code":
					z.ReturnOverrides.ResponseCode, bts, err = msgp.ReadIntBytes(bts)
					if err != nil {
						return
					}
				case "response_error":
					z.ReturnOverrides.ResponseError, bts, err = msgp.ReadStringBytes(bts)
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
func (z *CoProcessMiniRequestObject) Msgsize() (s int) {
	s = 1 + 8 + msgp.MapHeaderSize
	if z.Headers != nil {
		for zxvk, zbzg := range z.Headers {
			_ = zbzg
			s += msgp.StringPrefixSize + len(zxvk) + msgp.ArrayHeaderSize
			for zbai := range zbzg {
				s += msgp.StringPrefixSize + len(zbzg[zbai])
			}
		}
	}
	s += 12 + msgp.MapHeaderSize
	if z.SetHeaders != nil {
		for zcmr, zajw := range z.SetHeaders {
			_ = zajw
			s += msgp.StringPrefixSize + len(zcmr) + msgp.StringPrefixSize + len(zajw)
		}
	}
	s += 15 + msgp.ArrayHeaderSize
	for zwht := range z.DeleteHeaders {
		s += msgp.StringPrefixSize + len(z.DeleteHeaders[zwht])
	}
	s += 5 + msgp.StringPrefixSize + len(z.Body) + 4 + msgp.StringPrefixSize + len(z.URL) + 7 + msgp.MapHeaderSize
	if z.Params != nil {
		for zhct, zcua := range z.Params {
			_ = zcua
			s += msgp.StringPrefixSize + len(zhct) + msgp.ArrayHeaderSize
			for zxhx := range zcua {
				s += msgp.StringPrefixSize + len(zcua[zxhx])
			}
		}
	}
	s += 11 + msgp.MapHeaderSize
	if z.AddParams != nil {
		for zlqf, zdaf := range z.AddParams {
			_ = zdaf
			s += msgp.StringPrefixSize + len(zlqf) + msgp.StringPrefixSize + len(zdaf)
		}
	}
	s += 16 + msgp.MapHeaderSize
	if z.ExtendedParams != nil {
		for zpks, zjfb := range z.ExtendedParams {
			_ = zjfb
			s += msgp.StringPrefixSize + len(zpks) + msgp.ArrayHeaderSize
			for zcxo := range zjfb {
				s += msgp.StringPrefixSize + len(zjfb[zcxo])
			}
		}
	}
	s += 14 + msgp.ArrayHeaderSize
	for zeff := range z.DeleteParams {
		s += msgp.StringPrefixSize + len(z.DeleteParams[zeff])
	}
	s += 17 + 1 + 14 + msgp.IntSize + 15 + msgp.StringPrefixSize + len(z.ReturnOverrides.ResponseError)
	return
}

// DecodeMsg implements msgp.Decodable
func (z *CoProcessObject) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zkct uint32
	zkct, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zkct > 0 {
		zkct--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "hook_type":
			z.HookType, err = dc.ReadString()
			if err != nil {
				return
			}
		case "request":
			err = z.Request.DecodeMsg(dc)
			if err != nil {
				return
			}
		case "session":
			err = z.Session.DecodeMsg(dc)
			if err != nil {
				return
			}
		case "metadata":
			var ztmt uint32
			ztmt, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.Metadata == nil && ztmt > 0 {
				z.Metadata = make(map[string]string, ztmt)
			} else if len(z.Metadata) > 0 {
				for key, _ := range z.Metadata {
					delete(z.Metadata, key)
				}
			}
			for ztmt > 0 {
				ztmt--
				var zzdc string
				var zelx string
				zzdc, err = dc.ReadString()
				if err != nil {
					return
				}
				zelx, err = dc.ReadString()
				if err != nil {
					return
				}
				z.Metadata[zzdc] = zelx
			}
		case "spec":
			var ztco uint32
			ztco, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			if z.Spec == nil && ztco > 0 {
				z.Spec = make(map[string]string, ztco)
			} else if len(z.Spec) > 0 {
				for key, _ := range z.Spec {
					delete(z.Spec, key)
				}
			}
			for ztco > 0 {
				ztco--
				var zbal string
				var zjqz string
				zbal, err = dc.ReadString()
				if err != nil {
					return
				}
				zjqz, err = dc.ReadString()
				if err != nil {
					return
				}
				z.Spec[zbal] = zjqz
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
func (z *CoProcessObject) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 5
	// write "hook_type"
	err = en.Append(0x85, 0xa9, 0x68, 0x6f, 0x6f, 0x6b, 0x5f, 0x74, 0x79, 0x70, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteString(z.HookType)
	if err != nil {
		return
	}
	// write "request"
	err = en.Append(0xa7, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74)
	if err != nil {
		return err
	}
	err = z.Request.EncodeMsg(en)
	if err != nil {
		return
	}
	// write "session"
	err = en.Append(0xa7, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e)
	if err != nil {
		return err
	}
	err = z.Session.EncodeMsg(en)
	if err != nil {
		return
	}
	// write "metadata"
	err = en.Append(0xa8, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.Metadata)))
	if err != nil {
		return
	}
	for zzdc, zelx := range z.Metadata {
		err = en.WriteString(zzdc)
		if err != nil {
			return
		}
		err = en.WriteString(zelx)
		if err != nil {
			return
		}
	}
	// write "spec"
	err = en.Append(0xa4, 0x73, 0x70, 0x65, 0x63)
	if err != nil {
		return err
	}
	err = en.WriteMapHeader(uint32(len(z.Spec)))
	if err != nil {
		return
	}
	for zbal, zjqz := range z.Spec {
		err = en.WriteString(zbal)
		if err != nil {
			return
		}
		err = en.WriteString(zjqz)
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *CoProcessObject) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 5
	// string "hook_type"
	o = append(o, 0x85, 0xa9, 0x68, 0x6f, 0x6f, 0x6b, 0x5f, 0x74, 0x79, 0x70, 0x65)
	o = msgp.AppendString(o, z.HookType)
	// string "request"
	o = append(o, 0xa7, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74)
	o, err = z.Request.MarshalMsg(o)
	if err != nil {
		return
	}
	// string "session"
	o = append(o, 0xa7, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e)
	o, err = z.Session.MarshalMsg(o)
	if err != nil {
		return
	}
	// string "metadata"
	o = append(o, 0xa8, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61)
	o = msgp.AppendMapHeader(o, uint32(len(z.Metadata)))
	for zzdc, zelx := range z.Metadata {
		o = msgp.AppendString(o, zzdc)
		o = msgp.AppendString(o, zelx)
	}
	// string "spec"
	o = append(o, 0xa4, 0x73, 0x70, 0x65, 0x63)
	o = msgp.AppendMapHeader(o, uint32(len(z.Spec)))
	for zbal, zjqz := range z.Spec {
		o = msgp.AppendString(o, zbal)
		o = msgp.AppendString(o, zjqz)
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *CoProcessObject) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zana uint32
	zana, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zana > 0 {
		zana--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "hook_type":
			z.HookType, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "request":
			bts, err = z.Request.UnmarshalMsg(bts)
			if err != nil {
				return
			}
		case "session":
			bts, err = z.Session.UnmarshalMsg(bts)
			if err != nil {
				return
			}
		case "metadata":
			var ztyy uint32
			ztyy, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.Metadata == nil && ztyy > 0 {
				z.Metadata = make(map[string]string, ztyy)
			} else if len(z.Metadata) > 0 {
				for key, _ := range z.Metadata {
					delete(z.Metadata, key)
				}
			}
			for ztyy > 0 {
				var zzdc string
				var zelx string
				ztyy--
				zzdc, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				zelx, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				z.Metadata[zzdc] = zelx
			}
		case "spec":
			var zinl uint32
			zinl, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			if z.Spec == nil && zinl > 0 {
				z.Spec = make(map[string]string, zinl)
			} else if len(z.Spec) > 0 {
				for key, _ := range z.Spec {
					delete(z.Spec, key)
				}
			}
			for zinl > 0 {
				var zbal string
				var zjqz string
				zinl--
				zbal, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				zjqz, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
				z.Spec[zbal] = zjqz
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
func (z *CoProcessObject) Msgsize() (s int) {
	s = 1 + 10 + msgp.StringPrefixSize + len(z.HookType) + 8 + z.Request.Msgsize() + 8 + z.Session.Msgsize() + 9 + msgp.MapHeaderSize
	if z.Metadata != nil {
		for zzdc, zelx := range z.Metadata {
			_ = zelx
			s += msgp.StringPrefixSize + len(zzdc) + msgp.StringPrefixSize + len(zelx)
		}
	}
	s += 5 + msgp.MapHeaderSize
	if z.Spec != nil {
		for zbal, zjqz := range z.Spec {
			_ = zjqz
			s += msgp.StringPrefixSize + len(zbal) + msgp.StringPrefixSize + len(zjqz)
		}
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *CoProcessReturnOverrides) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zare uint32
	zare, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zare > 0 {
		zare--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "response_code":
			z.ResponseCode, err = dc.ReadInt()
			if err != nil {
				return
			}
		case "response_error":
			z.ResponseError, err = dc.ReadString()
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
func (z CoProcessReturnOverrides) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "response_code"
	err = en.Append(0x82, 0xad, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteInt(z.ResponseCode)
	if err != nil {
		return
	}
	// write "response_error"
	err = en.Append(0xae, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72)
	if err != nil {
		return err
	}
	err = en.WriteString(z.ResponseError)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z CoProcessReturnOverrides) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "response_code"
	o = append(o, 0x82, 0xad, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	o = msgp.AppendInt(o, z.ResponseCode)
	// string "response_error"
	o = append(o, 0xae, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72)
	o = msgp.AppendString(o, z.ResponseError)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *CoProcessReturnOverrides) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zljy uint32
	zljy, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zljy > 0 {
		zljy--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "response_code":
			z.ResponseCode, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				return
			}
		case "response_error":
			z.ResponseError, bts, err = msgp.ReadStringBytes(bts)
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
func (z CoProcessReturnOverrides) Msgsize() (s int) {
	s = 1 + 14 + msgp.IntSize + 15 + msgp.StringPrefixSize + len(z.ResponseError)
	return
}
