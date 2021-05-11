// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: envoy/extensions/filters/http/grpc_json_transcoder/v3/transcoder.proto

package envoy_extensions_filters_http_grpc_json_transcoder_v3

import (
	_ "github.com/cncf/udpa/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type GrpcJsonTranscoder_UrlUnescapeSpec int32

const (
	// URL path parameters will not decode RFC 6570 reserved characters.
	// For example, segment `%2f%23/%20%2523` is unescaped to `%2f%23/ %23`.
	GrpcJsonTranscoder_ALL_CHARACTERS_EXCEPT_RESERVED GrpcJsonTranscoder_UrlUnescapeSpec = 0
	// URL path parameters will be fully URI-decoded except in
	// cases of single segment matches in reserved expansion, where "%2F" will be
	// left encoded.
	// For example, segment `%2f%23/%20%2523` is unescaped to `%2f#/ %23`.
	GrpcJsonTranscoder_ALL_CHARACTERS_EXCEPT_SLASH GrpcJsonTranscoder_UrlUnescapeSpec = 1
	// URL path parameters will be fully URI-decoded.
	// For example, segment `%2f%23/%20%2523` is unescaped to `/#/ %23`.
	GrpcJsonTranscoder_ALL_CHARACTERS GrpcJsonTranscoder_UrlUnescapeSpec = 2
)

// Enum value maps for GrpcJsonTranscoder_UrlUnescapeSpec.
var (
	GrpcJsonTranscoder_UrlUnescapeSpec_name = map[int32]string{
		0: "ALL_CHARACTERS_EXCEPT_RESERVED",
		1: "ALL_CHARACTERS_EXCEPT_SLASH",
		2: "ALL_CHARACTERS",
	}
	GrpcJsonTranscoder_UrlUnescapeSpec_value = map[string]int32{
		"ALL_CHARACTERS_EXCEPT_RESERVED": 0,
		"ALL_CHARACTERS_EXCEPT_SLASH":    1,
		"ALL_CHARACTERS":                 2,
	}
)

func (x GrpcJsonTranscoder_UrlUnescapeSpec) Enum() *GrpcJsonTranscoder_UrlUnescapeSpec {
	p := new(GrpcJsonTranscoder_UrlUnescapeSpec)
	*p = x
	return p
}

func (x GrpcJsonTranscoder_UrlUnescapeSpec) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GrpcJsonTranscoder_UrlUnescapeSpec) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_enumTypes[0].Descriptor()
}

func (GrpcJsonTranscoder_UrlUnescapeSpec) Type() protoreflect.EnumType {
	return &file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_enumTypes[0]
}

func (x GrpcJsonTranscoder_UrlUnescapeSpec) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GrpcJsonTranscoder_UrlUnescapeSpec.Descriptor instead.
func (GrpcJsonTranscoder_UrlUnescapeSpec) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescGZIP(), []int{0, 0}
}

// [#next-free-field: 11]
type GrpcJsonTranscoder struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to DescriptorSet:
	//	*GrpcJsonTranscoder_ProtoDescriptor
	//	*GrpcJsonTranscoder_ProtoDescriptorBin
	DescriptorSet isGrpcJsonTranscoder_DescriptorSet `protobuf_oneof:"descriptor_set"`
	// A list of strings that
	// supplies the fully qualified service names (i.e. "package_name.service_name") that
	// the transcoder will translate. If the service name doesn't exist in ``proto_descriptor``,
	// Envoy will fail at startup. The ``proto_descriptor`` may contain more services than
	// the service names specified here, but they won't be translated.
	Services []string `protobuf:"bytes,2,rep,name=services,proto3" json:"services,omitempty"`
	// Control options for response JSON. These options are passed directly to
	// `JsonPrintOptions <https://developers.google.com/protocol-buffers/docs/reference/cpp/
	// google.protobuf.util.json_util#JsonPrintOptions>`_.
	PrintOptions *GrpcJsonTranscoder_PrintOptions `protobuf:"bytes,3,opt,name=print_options,json=printOptions,proto3" json:"print_options,omitempty"`
	// Whether to keep the incoming request route after the outgoing headers have been transformed to
	// the match the upstream gRPC service. Note: This means that routes for gRPC services that are
	// not transcoded cannot be used in combination with *match_incoming_request_route*.
	MatchIncomingRequestRoute bool `protobuf:"varint,5,opt,name=match_incoming_request_route,json=matchIncomingRequestRoute,proto3" json:"match_incoming_request_route,omitempty"`
	// A list of query parameters to be ignored for transcoding method mapping.
	// By default, the transcoder filter will not transcode a request if there are any
	// unknown/invalid query parameters.
	//
	// Example :
	//
	// .. code-block:: proto
	//
	//     service Bookstore {
	//       rpc GetShelf(GetShelfRequest) returns (Shelf) {
	//         option (google.api.http) = {
	//           get: "/shelves/{shelf}"
	//         };
	//       }
	//     }
	//
	//     message GetShelfRequest {
	//       int64 shelf = 1;
	//     }
	//
	//     message Shelf {}
	//
	// The request ``/shelves/100?foo=bar`` will not be mapped to ``GetShelf``` because variable
	// binding for ``foo`` is not defined. Adding ``foo`` to ``ignored_query_parameters`` will allow
	// the same request to be mapped to ``GetShelf``.
	IgnoredQueryParameters []string `protobuf:"bytes,6,rep,name=ignored_query_parameters,json=ignoredQueryParameters,proto3" json:"ignored_query_parameters,omitempty"`
	// Whether to route methods without the ``google.api.http`` option.
	//
	// Example :
	//
	// .. code-block:: proto
	//
	//     package bookstore;
	//
	//     service Bookstore {
	//       rpc GetShelf(GetShelfRequest) returns (Shelf) {}
	//     }
	//
	//     message GetShelfRequest {
	//       int64 shelf = 1;
	//     }
	//
	//     message Shelf {}
	//
	// The client could ``post`` a json body ``{"shelf": 1234}`` with the path of
	// ``/bookstore.Bookstore/GetShelfRequest`` to call ``GetShelfRequest``.
	AutoMapping bool `protobuf:"varint,7,opt,name=auto_mapping,json=autoMapping,proto3" json:"auto_mapping,omitempty"`
	// Whether to ignore query parameters that cannot be mapped to a corresponding
	// protobuf field. Use this if you cannot control the query parameters and do
	// not know them beforehand. Otherwise use ``ignored_query_parameters``.
	// Defaults to false.
	IgnoreUnknownQueryParameters bool `protobuf:"varint,8,opt,name=ignore_unknown_query_parameters,json=ignoreUnknownQueryParameters,proto3" json:"ignore_unknown_query_parameters,omitempty"`
	// Whether to convert gRPC status headers to JSON.
	// When trailer indicates a gRPC error and there was no HTTP body, take ``google.rpc.Status``
	// from the ``grpc-status-details-bin`` header and use it as JSON body.
	// If there was no such header, make ``google.rpc.Status`` out of the ``grpc-status`` and
	// ``grpc-message`` headers.
	// The error details types must be present in the ``proto_descriptor``.
	//
	// For example, if an upstream server replies with headers:
	//
	// .. code-block:: none
	//
	//     grpc-status: 5
	//     grpc-status-details-bin:
	//         CAUaMwoqdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUucnBjLlJlcXVlc3RJbmZvEgUKA3ItMQ
	//
	// The ``grpc-status-details-bin`` header contains a base64-encoded protobuf message
	// ``google.rpc.Status``. It will be transcoded into:
	//
	// .. code-block:: none
	//
	//     HTTP/1.1 404 Not Found
	//     content-type: application/json
	//
	//     {"code":5,"details":[{"@type":"type.googleapis.com/google.rpc.RequestInfo","requestId":"r-1"}]}
	//
	//  In order to transcode the message, the ``google.rpc.RequestInfo`` type from
	//  the ``google/rpc/error_details.proto`` should be included in the configured
	//  :ref:`proto descriptor set <config_grpc_json_generate_proto_descriptor_set>`.
	ConvertGrpcStatus bool `protobuf:"varint,9,opt,name=convert_grpc_status,json=convertGrpcStatus,proto3" json:"convert_grpc_status,omitempty"`
	// URL unescaping policy.
	// This spec is only applied when extracting variable with multiple segments.
	// For example, in case of `/foo/{x=*}/bar/{y=prefix/*}/{z=**}` `x` variable is single segment and `y` and `z` are multiple segments.
	// For a path with `/foo/first/bar/prefix/second/third/fourth`, `x=first`, `y=prefix/second`, `z=third/fourth`.
	// If this setting is not specified, the value defaults to :ref:`ALL_CHARACTERS_EXCEPT_RESERVED<envoy_api_enum_value_extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.UrlUnescapeSpec.ALL_CHARACTERS_EXCEPT_RESERVED>`.
	UrlUnescapeSpec GrpcJsonTranscoder_UrlUnescapeSpec `protobuf:"varint,10,opt,name=url_unescape_spec,json=urlUnescapeSpec,proto3,enum=envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder_UrlUnescapeSpec" json:"url_unescape_spec,omitempty"`
}

func (x *GrpcJsonTranscoder) Reset() {
	*x = GrpcJsonTranscoder{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GrpcJsonTranscoder) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GrpcJsonTranscoder) ProtoMessage() {}

func (x *GrpcJsonTranscoder) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GrpcJsonTranscoder.ProtoReflect.Descriptor instead.
func (*GrpcJsonTranscoder) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescGZIP(), []int{0}
}

func (m *GrpcJsonTranscoder) GetDescriptorSet() isGrpcJsonTranscoder_DescriptorSet {
	if m != nil {
		return m.DescriptorSet
	}
	return nil
}

func (x *GrpcJsonTranscoder) GetProtoDescriptor() string {
	if x, ok := x.GetDescriptorSet().(*GrpcJsonTranscoder_ProtoDescriptor); ok {
		return x.ProtoDescriptor
	}
	return ""
}

func (x *GrpcJsonTranscoder) GetProtoDescriptorBin() []byte {
	if x, ok := x.GetDescriptorSet().(*GrpcJsonTranscoder_ProtoDescriptorBin); ok {
		return x.ProtoDescriptorBin
	}
	return nil
}

func (x *GrpcJsonTranscoder) GetServices() []string {
	if x != nil {
		return x.Services
	}
	return nil
}

func (x *GrpcJsonTranscoder) GetPrintOptions() *GrpcJsonTranscoder_PrintOptions {
	if x != nil {
		return x.PrintOptions
	}
	return nil
}

func (x *GrpcJsonTranscoder) GetMatchIncomingRequestRoute() bool {
	if x != nil {
		return x.MatchIncomingRequestRoute
	}
	return false
}

func (x *GrpcJsonTranscoder) GetIgnoredQueryParameters() []string {
	if x != nil {
		return x.IgnoredQueryParameters
	}
	return nil
}

func (x *GrpcJsonTranscoder) GetAutoMapping() bool {
	if x != nil {
		return x.AutoMapping
	}
	return false
}

func (x *GrpcJsonTranscoder) GetIgnoreUnknownQueryParameters() bool {
	if x != nil {
		return x.IgnoreUnknownQueryParameters
	}
	return false
}

func (x *GrpcJsonTranscoder) GetConvertGrpcStatus() bool {
	if x != nil {
		return x.ConvertGrpcStatus
	}
	return false
}

func (x *GrpcJsonTranscoder) GetUrlUnescapeSpec() GrpcJsonTranscoder_UrlUnescapeSpec {
	if x != nil {
		return x.UrlUnescapeSpec
	}
	return GrpcJsonTranscoder_ALL_CHARACTERS_EXCEPT_RESERVED
}

type isGrpcJsonTranscoder_DescriptorSet interface {
	isGrpcJsonTranscoder_DescriptorSet()
}

type GrpcJsonTranscoder_ProtoDescriptor struct {
	// Supplies the filename of
	// :ref:`the proto descriptor set <config_grpc_json_generate_proto_descriptor_set>` for the gRPC
	// services.
	ProtoDescriptor string `protobuf:"bytes,1,opt,name=proto_descriptor,json=protoDescriptor,proto3,oneof"`
}

type GrpcJsonTranscoder_ProtoDescriptorBin struct {
	// Supplies the binary content of
	// :ref:`the proto descriptor set <config_grpc_json_generate_proto_descriptor_set>` for the gRPC
	// services.
	ProtoDescriptorBin []byte `protobuf:"bytes,4,opt,name=proto_descriptor_bin,json=protoDescriptorBin,proto3,oneof"`
}

func (*GrpcJsonTranscoder_ProtoDescriptor) isGrpcJsonTranscoder_DescriptorSet() {}

func (*GrpcJsonTranscoder_ProtoDescriptorBin) isGrpcJsonTranscoder_DescriptorSet() {}

type GrpcJsonTranscoder_PrintOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Whether to add spaces, line breaks and indentation to make the JSON
	// output easy to read. Defaults to false.
	AddWhitespace bool `protobuf:"varint,1,opt,name=add_whitespace,json=addWhitespace,proto3" json:"add_whitespace,omitempty"`
	// Whether to always print primitive fields. By default primitive
	// fields with default values will be omitted in JSON output. For
	// example, an int32 field set to 0 will be omitted. Setting this flag to
	// true will override the default behavior and print primitive fields
	// regardless of their values. Defaults to false.
	AlwaysPrintPrimitiveFields bool `protobuf:"varint,2,opt,name=always_print_primitive_fields,json=alwaysPrintPrimitiveFields,proto3" json:"always_print_primitive_fields,omitempty"`
	// Whether to always print enums as ints. By default they are rendered
	// as strings. Defaults to false.
	AlwaysPrintEnumsAsInts bool `protobuf:"varint,3,opt,name=always_print_enums_as_ints,json=alwaysPrintEnumsAsInts,proto3" json:"always_print_enums_as_ints,omitempty"`
	// Whether to preserve proto field names. By default protobuf will
	// generate JSON field names using the ``json_name`` option, or lower camel case,
	// in that order. Setting this flag will preserve the original field names. Defaults to false.
	PreserveProtoFieldNames bool `protobuf:"varint,4,opt,name=preserve_proto_field_names,json=preserveProtoFieldNames,proto3" json:"preserve_proto_field_names,omitempty"`
}

func (x *GrpcJsonTranscoder_PrintOptions) Reset() {
	*x = GrpcJsonTranscoder_PrintOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GrpcJsonTranscoder_PrintOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GrpcJsonTranscoder_PrintOptions) ProtoMessage() {}

func (x *GrpcJsonTranscoder_PrintOptions) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GrpcJsonTranscoder_PrintOptions.ProtoReflect.Descriptor instead.
func (*GrpcJsonTranscoder_PrintOptions) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescGZIP(), []int{0, 0}
}

func (x *GrpcJsonTranscoder_PrintOptions) GetAddWhitespace() bool {
	if x != nil {
		return x.AddWhitespace
	}
	return false
}

func (x *GrpcJsonTranscoder_PrintOptions) GetAlwaysPrintPrimitiveFields() bool {
	if x != nil {
		return x.AlwaysPrintPrimitiveFields
	}
	return false
}

func (x *GrpcJsonTranscoder_PrintOptions) GetAlwaysPrintEnumsAsInts() bool {
	if x != nil {
		return x.AlwaysPrintEnumsAsInts
	}
	return false
}

func (x *GrpcJsonTranscoder_PrintOptions) GetPreserveProtoFieldNames() bool {
	if x != nil {
		return x.PreserveProtoFieldNames
	}
	return false
}

var File_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDesc = []byte{
	0x0a, 0x46, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63,
	0x6f, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64,
	0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x35, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x6a, 0x73, 0x6f,
	0x6e, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a,
	0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21,
	0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc7, 0x09, 0x0a, 0x12, 0x47,
	0x72, 0x70, 0x63, 0x4a, 0x73, 0x6f, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65,
	0x72, 0x12, 0x2b, 0x0a, 0x10, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x5f, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x12, 0x32,
	0x0a, 0x14, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x5f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x6f, 0x72, 0x5f, 0x62, 0x69, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x12,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x42,
	0x69, 0x6e, 0x12, 0x24, 0x0a, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x09, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02, 0x08, 0x01, 0x52, 0x08,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x12, 0x7b, 0x0a, 0x0d, 0x70, 0x72, 0x69, 0x6e,
	0x74, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x56, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e,
	0x67, 0x72, 0x70, 0x63, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63,
	0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x47, 0x72, 0x70, 0x63, 0x4a, 0x73, 0x6f, 0x6e,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x74,
	0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x0c, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x1c, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x69,
	0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x19, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x49, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x38, 0x0a, 0x18, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
	0x64, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65,
	0x72, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x16, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
	0x64, 0x51, 0x75, 0x65, 0x72, 0x79, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73,
	0x12, 0x21, 0x0a, 0x0c, 0x61, 0x75, 0x74, 0x6f, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x61, 0x75, 0x74, 0x6f, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x12, 0x45, 0x0a, 0x1f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x5f, 0x75, 0x6e,
	0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70, 0x61, 0x72, 0x61,
	0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x1c, 0x69, 0x67,
	0x6e, 0x6f, 0x72, 0x65, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x12, 0x2e, 0x0a, 0x13, 0x63, 0x6f,
	0x6e, 0x76, 0x65, 0x72, 0x74, 0x5f, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x74,
	0x47, 0x72, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x8f, 0x01, 0x0a, 0x11, 0x75,
	0x72, 0x6c, 0x5f, 0x75, 0x6e, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65, 0x5f, 0x73, 0x70, 0x65, 0x63,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x59, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x6a, 0x73, 0x6f, 0x6e,
	0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x47,
	0x72, 0x70, 0x63, 0x4a, 0x73, 0x6f, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65,
	0x72, 0x2e, 0x55, 0x72, 0x6c, 0x55, 0x6e, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65, 0x53, 0x70, 0x65,
	0x63, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x82, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0f, 0x75, 0x72, 0x6c,
	0x55, 0x6e, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65, 0x53, 0x70, 0x65, 0x63, 0x1a, 0xc0, 0x02, 0x0a,
	0x0c, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x25, 0x0a,
	0x0e, 0x61, 0x64, 0x64, 0x5f, 0x77, 0x68, 0x69, 0x74, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x61, 0x64, 0x64, 0x57, 0x68, 0x69, 0x74, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x12, 0x41, 0x0a, 0x1d, 0x61, 0x6c, 0x77, 0x61, 0x79, 0x73, 0x5f, 0x70,
	0x72, 0x69, 0x6e, 0x74, 0x5f, 0x70, 0x72, 0x69, 0x6d, 0x69, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x66,
	0x69, 0x65, 0x6c, 0x64, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x1a, 0x61, 0x6c, 0x77,
	0x61, 0x79, 0x73, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x50, 0x72, 0x69, 0x6d, 0x69, 0x74, 0x69, 0x76,
	0x65, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x12, 0x3a, 0x0a, 0x1a, 0x61, 0x6c, 0x77, 0x61, 0x79,
	0x73, 0x5f, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x75, 0x6d, 0x73, 0x5f, 0x61, 0x73,
	0x5f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x16, 0x61, 0x6c, 0x77,
	0x61, 0x79, 0x73, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x45, 0x6e, 0x75, 0x6d, 0x73, 0x41, 0x73, 0x49,
	0x6e, 0x74, 0x73, 0x12, 0x3b, 0x0a, 0x1a, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x5f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x17, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x3a, 0x4d, 0x9a, 0xc5, 0x88, 0x1e, 0x48, 0x0a, 0x46, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2e, 0x68, 0x74, 0x74,
	0x70, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x32, 0x2e,
	0x47, 0x72, 0x70, 0x63, 0x4a, 0x73, 0x6f, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64,
	0x65, 0x72, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22,
	0x6a, 0x0a, 0x0f, 0x55, 0x72, 0x6c, 0x55, 0x6e, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65, 0x53, 0x70,
	0x65, 0x63, 0x12, 0x22, 0x0a, 0x1e, 0x41, 0x4c, 0x4c, 0x5f, 0x43, 0x48, 0x41, 0x52, 0x41, 0x43,
	0x54, 0x45, 0x52, 0x53, 0x5f, 0x45, 0x58, 0x43, 0x45, 0x50, 0x54, 0x5f, 0x52, 0x45, 0x53, 0x45,
	0x52, 0x56, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1f, 0x0a, 0x1b, 0x41, 0x4c, 0x4c, 0x5f, 0x43, 0x48,
	0x41, 0x52, 0x41, 0x43, 0x54, 0x45, 0x52, 0x53, 0x5f, 0x45, 0x58, 0x43, 0x45, 0x50, 0x54, 0x5f,
	0x53, 0x4c, 0x41, 0x53, 0x48, 0x10, 0x01, 0x12, 0x12, 0x0a, 0x0e, 0x41, 0x4c, 0x4c, 0x5f, 0x43,
	0x48, 0x41, 0x52, 0x41, 0x43, 0x54, 0x45, 0x52, 0x53, 0x10, 0x02, 0x3a, 0x40, 0x9a, 0xc5, 0x88,
	0x1e, 0x3b, 0x0a, 0x39, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x47, 0x72, 0x70, 0x63, 0x4a,
	0x73, 0x6f, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x42, 0x15, 0x0a,
	0x0e, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x5f, 0x73, 0x65, 0x74, 0x12,
	0x03, 0xf8, 0x42, 0x01, 0x42, 0x60, 0x0a, 0x43, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68,
	0x74, 0x74, 0x70, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x42, 0x0f, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x63, 0x6f, 0x64, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xba, 0x80,
	0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescData = file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDesc
)

func file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescData)
	})
	return file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDescData
}

var file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_goTypes = []interface{}{
	(GrpcJsonTranscoder_UrlUnescapeSpec)(0), // 0: envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.UrlUnescapeSpec
	(*GrpcJsonTranscoder)(nil),              // 1: envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder
	(*GrpcJsonTranscoder_PrintOptions)(nil), // 2: envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.PrintOptions
}
var file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_depIdxs = []int32{
	2, // 0: envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.print_options:type_name -> envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.PrintOptions
	0, // 1: envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.url_unescape_spec:type_name -> envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder.UrlUnescapeSpec
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_init() }
func file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_init() {
	if File_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GrpcJsonTranscoder); i {
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
		file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GrpcJsonTranscoder_PrintOptions); i {
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
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*GrpcJsonTranscoder_ProtoDescriptor)(nil),
		(*GrpcJsonTranscoder_ProtoDescriptorBin)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_depIdxs,
		EnumInfos:         file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_enumTypes,
		MessageInfos:      file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto = out.File
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_rawDesc = nil
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_goTypes = nil
	file_envoy_extensions_filters_http_grpc_json_transcoder_v3_transcoder_proto_depIdxs = nil
}
