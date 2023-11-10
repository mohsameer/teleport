// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: accessgraph/v1alpha/query.proto

package accessgraphv1alpha

import (
	types "github.com/gravitational/teleport/api/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Node is a node in the access graph.
type Node struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string            `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Kind       string            `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	SubKind    string            `protobuf:"bytes,3,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	Name       string            `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	Labels     map[string]string `protobuf:"bytes,5,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Hostname   string            `protobuf:"bytes,6,opt,name=hostname,proto3" json:"hostname,omitempty"`
	Properties map[string]string `protobuf:"bytes,7,rep,name=properties,proto3" json:"properties,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{0}
}

func (x *Node) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Node) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *Node) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *Node) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Node) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *Node) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *Node) GetProperties() map[string]string {
	if x != nil {
		return x.Properties
	}
	return nil
}

// Edge is an edge in the access graph.
type Edge struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From string `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	To   string `protobuf:"bytes,2,opt,name=to,proto3" json:"to,omitempty"`
	Type string `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
}

func (x *Edge) Reset() {
	*x = Edge{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Edge) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Edge) ProtoMessage() {}

func (x *Edge) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Edge.ProtoReflect.Descriptor instead.
func (*Edge) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{1}
}

func (x *Edge) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *Edge) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *Edge) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

// QueryRequest is a request to query the access graph.
type QueryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// query is a SQL query.
	Query string `protobuf:"bytes,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *QueryRequest) Reset() {
	*x = QueryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryRequest) ProtoMessage() {}

func (x *QueryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryRequest.ProtoReflect.Descriptor instead.
func (*QueryRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{2}
}

func (x *QueryRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

// QueryResponse is a response to a query.
type QueryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nodes []*Node `protobuf:"bytes,1,rep,name=nodes,proto3" json:"nodes,omitempty"`
	Edges []*Edge `protobuf:"bytes,2,rep,name=edges,proto3" json:"edges,omitempty"`
}

func (x *QueryResponse) Reset() {
	*x = QueryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryResponse) ProtoMessage() {}

func (x *QueryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryResponse.ProtoReflect.Descriptor instead.
func (*QueryResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{3}
}

func (x *QueryResponse) GetNodes() []*Node {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *QueryResponse) GetEdges() []*Edge {
	if x != nil {
		return x.Edges
	}
	return nil
}

// GetFileRequest is a request to get a file.
type GetFileRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filepath string `protobuf:"bytes,1,opt,name=filepath,proto3" json:"filepath,omitempty"`
}

func (x *GetFileRequest) Reset() {
	*x = GetFileRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetFileRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetFileRequest) ProtoMessage() {}

func (x *GetFileRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetFileRequest.ProtoReflect.Descriptor instead.
func (*GetFileRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{4}
}

func (x *GetFileRequest) GetFilepath() string {
	if x != nil {
		return x.Filepath
	}
	return ""
}

// GetFileResponse is a response to a file request.
type GetFileResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *GetFileResponse) Reset() {
	*x = GetFileResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetFileResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetFileResponse) ProtoMessage() {}

func (x *GetFileResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetFileResponse.ProtoReflect.Descriptor instead.
func (*GetFileResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{5}
}

func (x *GetFileResponse) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

// ResourceList is a list of resources to send to the access graph.
type ResourceList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Resources []*ResourceEntry `protobuf:"bytes,1,rep,name=resources,proto3" json:"resources,omitempty"`
}

func (x *ResourceList) Reset() {
	*x = ResourceList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceList) ProtoMessage() {}

func (x *ResourceList) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceList.ProtoReflect.Descriptor instead.
func (*ResourceList) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{6}
}

func (x *ResourceList) GetResources() []*ResourceEntry {
	if x != nil {
		return x.Resources
	}
	return nil
}

// ResourceEntry is a wrapper for the supported resource types.
type ResourceEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Resource:
	//
	//	*ResourceEntry_User
	//	*ResourceEntry_Role
	//	*ResourceEntry_Server
	//	*ResourceEntry_AccessRequest
	Resource isResourceEntry_Resource `protobuf_oneof:"resource"`
}

func (x *ResourceEntry) Reset() {
	*x = ResourceEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceEntry) ProtoMessage() {}

func (x *ResourceEntry) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceEntry.ProtoReflect.Descriptor instead.
func (*ResourceEntry) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{7}
}

func (m *ResourceEntry) GetResource() isResourceEntry_Resource {
	if m != nil {
		return m.Resource
	}
	return nil
}

func (x *ResourceEntry) GetUser() *types.UserV2 {
	if x, ok := x.GetResource().(*ResourceEntry_User); ok {
		return x.User
	}
	return nil
}

func (x *ResourceEntry) GetRole() *types.RoleV6 {
	if x, ok := x.GetResource().(*ResourceEntry_Role); ok {
		return x.Role
	}
	return nil
}

func (x *ResourceEntry) GetServer() *types.ServerV2 {
	if x, ok := x.GetResource().(*ResourceEntry_Server); ok {
		return x.Server
	}
	return nil
}

func (x *ResourceEntry) GetAccessRequest() *types.AccessRequestV3 {
	if x, ok := x.GetResource().(*ResourceEntry_AccessRequest); ok {
		return x.AccessRequest
	}
	return nil
}

type isResourceEntry_Resource interface {
	isResourceEntry_Resource()
}

type ResourceEntry_User struct {
	// User is a user resource
	User *types.UserV2 `protobuf:"bytes,1,opt,name=user,proto3,oneof"`
}

type ResourceEntry_Role struct {
	// Role is a role resource
	Role *types.RoleV6 `protobuf:"bytes,2,opt,name=role,proto3,oneof"`
}

type ResourceEntry_Server struct {
	// Server is a node or proxy resource
	Server *types.ServerV2 `protobuf:"bytes,3,opt,name=server,proto3,oneof"`
}

type ResourceEntry_AccessRequest struct {
	// AccessRequest is a resource for access requests
	AccessRequest *types.AccessRequestV3 `protobuf:"bytes,4,opt,name=access_request,json=accessRequest,proto3,oneof"`
}

func (*ResourceEntry_User) isResourceEntry_Resource() {}

func (*ResourceEntry_Role) isResourceEntry_Resource() {}

func (*ResourceEntry_Server) isResourceEntry_Resource() {}

func (*ResourceEntry_AccessRequest) isResourceEntry_Resource() {}

// EventsStreamRequest is a request to send commands to the access graph.
// This command is used to sync the access graph with the Teleport database state.
type EventsStreamRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// operation contains the desired operation
	//
	// Types that are assignable to Operation:
	//
	//	*EventsStreamRequest_Sync
	//	*EventsStreamRequest_Upsert
	//	*EventsStreamRequest_Delete
	Operation isEventsStreamRequest_Operation `protobuf_oneof:"operation"`
}

func (x *EventsStreamRequest) Reset() {
	*x = EventsStreamRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventsStreamRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventsStreamRequest) ProtoMessage() {}

func (x *EventsStreamRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventsStreamRequest.ProtoReflect.Descriptor instead.
func (*EventsStreamRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{8}
}

func (m *EventsStreamRequest) GetOperation() isEventsStreamRequest_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (x *EventsStreamRequest) GetSync() *emptypb.Empty {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Sync); ok {
		return x.Sync
	}
	return nil
}

func (x *EventsStreamRequest) GetUpsert() *ResourceList {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Upsert); ok {
		return x.Upsert
	}
	return nil
}

func (x *EventsStreamRequest) GetDelete() *types.ResourceHeader {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Delete); ok {
		return x.Delete
	}
	return nil
}

type isEventsStreamRequest_Operation interface {
	isEventsStreamRequest_Operation()
}

type EventsStreamRequest_Sync struct {
	// sync is a command to sync the access graph with the Teleport database state.
	// it's issued once Teleport finishes syncing all resources with the database.
	Sync *emptypb.Empty `protobuf:"bytes,1,opt,name=sync,proto3,oneof"`
}

type EventsStreamRequest_Upsert struct {
	// upsert is a command to put a resource into the access graph or update it.
	Upsert *ResourceList `protobuf:"bytes,2,opt,name=upsert,proto3,oneof"`
}

type EventsStreamRequest_Delete struct {
	// delete is a command to delete a resource from the access graph when it's deleted from Teleport.
	Delete *types.ResourceHeader `protobuf:"bytes,3,opt,name=delete,proto3,oneof"`
}

func (*EventsStreamRequest_Sync) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_Upsert) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_Delete) isEventsStreamRequest_Operation() {}

// EventsStreamResponse is an empty response from EventsStream endpoint.
type EventsStreamResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EventsStreamResponse) Reset() {
	*x = EventsStreamResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_query_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventsStreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventsStreamResponse) ProtoMessage() {}

func (x *EventsStreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_query_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventsStreamResponse.ProtoReflect.Descriptor instead.
func (*EventsStreamResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_query_proto_rawDescGZIP(), []int{9}
}

var File_accessgraph_v1alpha_query_proto protoreflect.FileDescriptor

var file_accessgraph_v1alpha_query_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x13, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x65,
	0x67, 0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf9, 0x02, 0x0a, 0x04, 0x4e, 0x6f, 0x64, 0x65, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b,
	0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x3d, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x25, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x4c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c,
	0x73, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x49, 0x0a,
	0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x29, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x50, 0x72, 0x6f,
	0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x70, 0x72,
	0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65,
	0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x1a, 0x3d, 0x0a, 0x0f, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x22, 0x3e, 0x0a, 0x04, 0x45, 0x64, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72,
	0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e,
	0x0a, 0x02, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x22, 0x24, 0x0a, 0x0c, 0x51, 0x75, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x71, 0x0a, 0x0d, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x05, 0x6e, 0x6f, 0x64,
	0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e,
	0x6f, 0x64, 0x65, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x2f, 0x0a, 0x05, 0x65, 0x64,
	0x67, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e,
	0x45, 0x64, 0x67, 0x65, 0x52, 0x05, 0x65, 0x64, 0x67, 0x65, 0x73, 0x22, 0x2c, 0x0a, 0x0e, 0x47,
	0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a,
	0x08, 0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x22, 0x25, 0x0a, 0x0f, 0x47, 0x65, 0x74,
	0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x50, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x40, 0x0a, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70,
	0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x22, 0xd1, 0x01, 0x0a, 0x0d, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x23, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x56,
	0x32, 0x48, 0x00, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x23, 0x0a, 0x04, 0x72, 0x6f, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x52, 0x6f, 0x6c, 0x65, 0x56, 0x36, 0x48, 0x00, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x29,
	0x0a, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x56, 0x32, 0x48,
	0x00, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x3f, 0x0a, 0x0e, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x16, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x56, 0x33, 0x48, 0x00, 0x52, 0x0d, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xbe, 0x01, 0x0a, 0x13, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2c,
	0x0a, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x48, 0x00, 0x52, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x12, 0x3b, 0x0a, 0x06,
	0x75, 0x70, 0x73, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x48,
	0x00, 0x52, 0x06, 0x75, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x2f, 0x0a, 0x06, 0x64, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x48, 0x00, 0x52, 0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x42, 0x0b, 0x0a, 0x09, 0x6f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x16, 0x0a, 0x14, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32,
	0xa1, 0x02, 0x0a, 0x12, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47, 0x72, 0x61, 0x70, 0x68, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x4e, 0x0a, 0x05, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12,
	0x21, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x22, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x54, 0x0a, 0x07, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6c,
	0x65, 0x12, 0x23, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x47, 0x65, 0x74,
	0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x65, 0x0a, 0x0c,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x28, 0x2e, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x28, 0x01, 0x42, 0x57, 0x5a, 0x55, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70,
	0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x67, 0x72, 0x61, 0x70, 0x68, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_accessgraph_v1alpha_query_proto_rawDescOnce sync.Once
	file_accessgraph_v1alpha_query_proto_rawDescData = file_accessgraph_v1alpha_query_proto_rawDesc
)

func file_accessgraph_v1alpha_query_proto_rawDescGZIP() []byte {
	file_accessgraph_v1alpha_query_proto_rawDescOnce.Do(func() {
		file_accessgraph_v1alpha_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_accessgraph_v1alpha_query_proto_rawDescData)
	})
	return file_accessgraph_v1alpha_query_proto_rawDescData
}

var file_accessgraph_v1alpha_query_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_accessgraph_v1alpha_query_proto_goTypes = []interface{}{
	(*Node)(nil),                  // 0: accessgraph.v1alpha.Node
	(*Edge)(nil),                  // 1: accessgraph.v1alpha.Edge
	(*QueryRequest)(nil),          // 2: accessgraph.v1alpha.QueryRequest
	(*QueryResponse)(nil),         // 3: accessgraph.v1alpha.QueryResponse
	(*GetFileRequest)(nil),        // 4: accessgraph.v1alpha.GetFileRequest
	(*GetFileResponse)(nil),       // 5: accessgraph.v1alpha.GetFileResponse
	(*ResourceList)(nil),          // 6: accessgraph.v1alpha.ResourceList
	(*ResourceEntry)(nil),         // 7: accessgraph.v1alpha.ResourceEntry
	(*EventsStreamRequest)(nil),   // 8: accessgraph.v1alpha.EventsStreamRequest
	(*EventsStreamResponse)(nil),  // 9: accessgraph.v1alpha.EventsStreamResponse
	nil,                           // 10: accessgraph.v1alpha.Node.LabelsEntry
	nil,                           // 11: accessgraph.v1alpha.Node.PropertiesEntry
	(*types.UserV2)(nil),          // 12: types.UserV2
	(*types.RoleV6)(nil),          // 13: types.RoleV6
	(*types.ServerV2)(nil),        // 14: types.ServerV2
	(*types.AccessRequestV3)(nil), // 15: types.AccessRequestV3
	(*emptypb.Empty)(nil),         // 16: google.protobuf.Empty
	(*types.ResourceHeader)(nil),  // 17: types.ResourceHeader
}
var file_accessgraph_v1alpha_query_proto_depIdxs = []int32{
	10, // 0: accessgraph.v1alpha.Node.labels:type_name -> accessgraph.v1alpha.Node.LabelsEntry
	11, // 1: accessgraph.v1alpha.Node.properties:type_name -> accessgraph.v1alpha.Node.PropertiesEntry
	0,  // 2: accessgraph.v1alpha.QueryResponse.nodes:type_name -> accessgraph.v1alpha.Node
	1,  // 3: accessgraph.v1alpha.QueryResponse.edges:type_name -> accessgraph.v1alpha.Edge
	7,  // 4: accessgraph.v1alpha.ResourceList.resources:type_name -> accessgraph.v1alpha.ResourceEntry
	12, // 5: accessgraph.v1alpha.ResourceEntry.user:type_name -> types.UserV2
	13, // 6: accessgraph.v1alpha.ResourceEntry.role:type_name -> types.RoleV6
	14, // 7: accessgraph.v1alpha.ResourceEntry.server:type_name -> types.ServerV2
	15, // 8: accessgraph.v1alpha.ResourceEntry.access_request:type_name -> types.AccessRequestV3
	16, // 9: accessgraph.v1alpha.EventsStreamRequest.sync:type_name -> google.protobuf.Empty
	6,  // 10: accessgraph.v1alpha.EventsStreamRequest.upsert:type_name -> accessgraph.v1alpha.ResourceList
	17, // 11: accessgraph.v1alpha.EventsStreamRequest.delete:type_name -> types.ResourceHeader
	2,  // 12: accessgraph.v1alpha.AccessGraphService.Query:input_type -> accessgraph.v1alpha.QueryRequest
	4,  // 13: accessgraph.v1alpha.AccessGraphService.GetFile:input_type -> accessgraph.v1alpha.GetFileRequest
	8,  // 14: accessgraph.v1alpha.AccessGraphService.EventsStream:input_type -> accessgraph.v1alpha.EventsStreamRequest
	3,  // 15: accessgraph.v1alpha.AccessGraphService.Query:output_type -> accessgraph.v1alpha.QueryResponse
	5,  // 16: accessgraph.v1alpha.AccessGraphService.GetFile:output_type -> accessgraph.v1alpha.GetFileResponse
	9,  // 17: accessgraph.v1alpha.AccessGraphService.EventsStream:output_type -> accessgraph.v1alpha.EventsStreamResponse
	15, // [15:18] is the sub-list for method output_type
	12, // [12:15] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_accessgraph_v1alpha_query_proto_init() }
func file_accessgraph_v1alpha_query_proto_init() {
	if File_accessgraph_v1alpha_query_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_accessgraph_v1alpha_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Node); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Edge); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryRequest); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryResponse); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetFileRequest); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetFileResponse); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceList); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceEntry); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventsStreamRequest); i {
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
		file_accessgraph_v1alpha_query_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventsStreamResponse); i {
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
	file_accessgraph_v1alpha_query_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*ResourceEntry_User)(nil),
		(*ResourceEntry_Role)(nil),
		(*ResourceEntry_Server)(nil),
		(*ResourceEntry_AccessRequest)(nil),
	}
	file_accessgraph_v1alpha_query_proto_msgTypes[8].OneofWrappers = []interface{}{
		(*EventsStreamRequest_Sync)(nil),
		(*EventsStreamRequest_Upsert)(nil),
		(*EventsStreamRequest_Delete)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_accessgraph_v1alpha_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_accessgraph_v1alpha_query_proto_goTypes,
		DependencyIndexes: file_accessgraph_v1alpha_query_proto_depIdxs,
		MessageInfos:      file_accessgraph_v1alpha_query_proto_msgTypes,
	}.Build()
	File_accessgraph_v1alpha_query_proto = out.File
	file_accessgraph_v1alpha_query_proto_rawDesc = nil
	file_accessgraph_v1alpha_query_proto_goTypes = nil
	file_accessgraph_v1alpha_query_proto_depIdxs = nil
}
