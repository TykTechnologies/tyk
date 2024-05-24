// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v5.26.1
// source: coprocess_return_overrides.proto

package coprocess

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Used to override the response for a given HTTP request
//
// When returned within an Object for a given HTTP request, the upstream reponse
// is replaced with the fields encapsulated within ReturnOverrides
type ReturnOverrides struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Override upstream response status code
	ResponseCode int32 `protobuf:"varint,1,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`
	// Override upstream response error message
	ResponseError string `protobuf:"bytes,2,opt,name=response_error,json=responseError,proto3" json:"response_error,omitempty"`
	// Override upstream response headers
	Headers map[string]string `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// If true then override upstream error response with response_error
	OverrideError bool `protobuf:"varint,4,opt,name=override_error,json=overrideError,proto3" json:"override_error,omitempty"`
	// Alias of response_error, contains the response body
	ResponseBody string `protobuf:"bytes,5,opt,name=response_body,json=responseBody,proto3" json:"response_body,omitempty"`
}

func (x *ReturnOverrides) Reset() {
	*x = ReturnOverrides{}
	if protoimpl.UnsafeEnabled {
		mi := &file_coprocess_return_overrides_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReturnOverrides) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReturnOverrides) ProtoMessage() {}

func (x *ReturnOverrides) ProtoReflect() protoreflect.Message {
	mi := &file_coprocess_return_overrides_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReturnOverrides.ProtoReflect.Descriptor instead.
func (*ReturnOverrides) Descriptor() ([]byte, []int) {
	return file_coprocess_return_overrides_proto_rawDescGZIP(), []int{0}
}

func (x *ReturnOverrides) GetResponseCode() int32 {
	if x != nil {
		return x.ResponseCode
	}
	return 0
}

func (x *ReturnOverrides) GetResponseError() string {
	if x != nil {
		return x.ResponseError
	}
	return ""
}

func (x *ReturnOverrides) GetHeaders() map[string]string {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *ReturnOverrides) GetOverrideError() bool {
	if x != nil {
		return x.OverrideError
	}
	return false
}

func (x *ReturnOverrides) GetResponseBody() string {
	if x != nil {
		return x.ResponseBody
	}
	return ""
}

var File_coprocess_return_overrides_proto protoreflect.FileDescriptor

var file_coprocess_return_overrides_proto_rawDesc = []byte{
	0x0a, 0x20, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x65, 0x74, 0x75,
	0x72, 0x6e, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x09, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x22, 0xa8, 0x02,
	0x0a, 0x0f, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x4f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65,
	0x73, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x41, 0x0a,
	0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27,
	0x2e, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x52, 0x65, 0x74, 0x75, 0x72,
	0x6e, 0x4f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x73, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x12, 0x25, 0x0a, 0x0e, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x5f, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69,
	0x64, 0x65, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x6f, 0x64, 0x79, 0x1a, 0x3a, 0x0a, 0x0c,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x0c, 0x5a, 0x0a, 0x2f, 0x63, 0x6f, 0x70,
	0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_coprocess_return_overrides_proto_rawDescOnce sync.Once
	file_coprocess_return_overrides_proto_rawDescData = file_coprocess_return_overrides_proto_rawDesc
)

func file_coprocess_return_overrides_proto_rawDescGZIP() []byte {
	file_coprocess_return_overrides_proto_rawDescOnce.Do(func() {
		file_coprocess_return_overrides_proto_rawDescData = protoimpl.X.CompressGZIP(file_coprocess_return_overrides_proto_rawDescData)
	})
	return file_coprocess_return_overrides_proto_rawDescData
}

var file_coprocess_return_overrides_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_coprocess_return_overrides_proto_goTypes = []interface{}{
	(*ReturnOverrides)(nil), // 0: coprocess.ReturnOverrides
	nil,                     // 1: coprocess.ReturnOverrides.HeadersEntry
}
var file_coprocess_return_overrides_proto_depIdxs = []int32{
	1, // 0: coprocess.ReturnOverrides.headers:type_name -> coprocess.ReturnOverrides.HeadersEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_coprocess_return_overrides_proto_init() }
func file_coprocess_return_overrides_proto_init() {
	if File_coprocess_return_overrides_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_coprocess_return_overrides_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReturnOverrides); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_coprocess_return_overrides_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_coprocess_return_overrides_proto_goTypes,
		DependencyIndexes: file_coprocess_return_overrides_proto_depIdxs,
		MessageInfos:      file_coprocess_return_overrides_proto_msgTypes,
	}.Build()
	File_coprocess_return_overrides_proto = out.File
	file_coprocess_return_overrides_proto_rawDesc = nil
	file_coprocess_return_overrides_proto_goTypes = nil
	file_coprocess_return_overrides_proto_depIdxs = nil
}
