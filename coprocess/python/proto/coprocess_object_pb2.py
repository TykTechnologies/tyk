# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: coprocess_object.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import coprocess_mini_request_object_pb2 as coprocess__mini__request__object__pb2
import coprocess_response_object_pb2 as coprocess__response__object__pb2
import coprocess_session_state_pb2 as coprocess__session__state__pb2
import coprocess_common_pb2 as coprocess__common__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='coprocess_object.proto',
  package='coprocess',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x16\x63oprocess_object.proto\x12\tcoprocess\x1a#coprocess_mini_request_object.proto\x1a\x1f\x63oprocess_response_object.proto\x1a\x1d\x63oprocess_session_state.proto\x1a\x16\x63oprocess_common.proto\"\x85\x03\n\x06Object\x12&\n\thook_type\x18\x01 \x01(\x0e\x32\x13.coprocess.HookType\x12\x11\n\thook_name\x18\x02 \x01(\t\x12-\n\x07request\x18\x03 \x01(\x0b\x32\x1c.coprocess.MiniRequestObject\x12(\n\x07session\x18\x04 \x01(\x0b\x32\x17.coprocess.SessionState\x12\x31\n\x08metadata\x18\x05 \x03(\x0b\x32\x1f.coprocess.Object.MetadataEntry\x12)\n\x04spec\x18\x06 \x03(\x0b\x32\x1b.coprocess.Object.SpecEntry\x12+\n\x08response\x18\x07 \x01(\x0b\x32\x19.coprocess.ResponseObject\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a+\n\tSpecEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x18\n\x05\x45vent\x12\x0f\n\x07payload\x18\x01 \x01(\t\"\x0c\n\nEventReply2|\n\nDispatcher\x12\x32\n\x08\x44ispatch\x12\x11.coprocess.Object\x1a\x11.coprocess.Object\"\x00\x12:\n\rDispatchEvent\x12\x10.coprocess.Event\x1a\x15.coprocess.EventReply\"\x00\x62\x06proto3'
  ,
  dependencies=[coprocess__mini__request__object__pb2.DESCRIPTOR,coprocess__response__object__pb2.DESCRIPTOR,coprocess__session__state__pb2.DESCRIPTOR,coprocess__common__pb2.DESCRIPTOR,])




_OBJECT_METADATAENTRY = _descriptor.Descriptor(
  name='MetadataEntry',
  full_name='coprocess.Object.MetadataEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.Object.MetadataEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.Object.MetadataEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=460,
  serialized_end=507,
)

_OBJECT_SPECENTRY = _descriptor.Descriptor(
  name='SpecEntry',
  full_name='coprocess.Object.SpecEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.Object.SpecEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.Object.SpecEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=509,
  serialized_end=552,
)

_OBJECT = _descriptor.Descriptor(
  name='Object',
  full_name='coprocess.Object',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hook_type', full_name='coprocess.Object.hook_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='hook_name', full_name='coprocess.Object.hook_name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='request', full_name='coprocess.Object.request', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='session', full_name='coprocess.Object.session', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='metadata', full_name='coprocess.Object.metadata', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='spec', full_name='coprocess.Object.spec', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='response', full_name='coprocess.Object.response', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_OBJECT_METADATAENTRY, _OBJECT_SPECENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=163,
  serialized_end=552,
)


_EVENT = _descriptor.Descriptor(
  name='Event',
  full_name='coprocess.Event',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='payload', full_name='coprocess.Event.payload', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=554,
  serialized_end=578,
)


_EVENTREPLY = _descriptor.Descriptor(
  name='EventReply',
  full_name='coprocess.EventReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=580,
  serialized_end=592,
)

_OBJECT_METADATAENTRY.containing_type = _OBJECT
_OBJECT_SPECENTRY.containing_type = _OBJECT
_OBJECT.fields_by_name['hook_type'].enum_type = coprocess__common__pb2._HOOKTYPE
_OBJECT.fields_by_name['request'].message_type = coprocess__mini__request__object__pb2._MINIREQUESTOBJECT
_OBJECT.fields_by_name['session'].message_type = coprocess__session__state__pb2._SESSIONSTATE
_OBJECT.fields_by_name['metadata'].message_type = _OBJECT_METADATAENTRY
_OBJECT.fields_by_name['spec'].message_type = _OBJECT_SPECENTRY
_OBJECT.fields_by_name['response'].message_type = coprocess__response__object__pb2._RESPONSEOBJECT
DESCRIPTOR.message_types_by_name['Object'] = _OBJECT
DESCRIPTOR.message_types_by_name['Event'] = _EVENT
DESCRIPTOR.message_types_by_name['EventReply'] = _EVENTREPLY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Object = _reflection.GeneratedProtocolMessageType('Object', (_message.Message,), {

  'MetadataEntry' : _reflection.GeneratedProtocolMessageType('MetadataEntry', (_message.Message,), {
    'DESCRIPTOR' : _OBJECT_METADATAENTRY,
    '__module__' : 'coprocess_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.Object.MetadataEntry)
    })
  ,

  'SpecEntry' : _reflection.GeneratedProtocolMessageType('SpecEntry', (_message.Message,), {
    'DESCRIPTOR' : _OBJECT_SPECENTRY,
    '__module__' : 'coprocess_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.Object.SpecEntry)
    })
  ,
  'DESCRIPTOR' : _OBJECT,
  '__module__' : 'coprocess_object_pb2'
  # @@protoc_insertion_point(class_scope:coprocess.Object)
  })
_sym_db.RegisterMessage(Object)
_sym_db.RegisterMessage(Object.MetadataEntry)
_sym_db.RegisterMessage(Object.SpecEntry)

Event = _reflection.GeneratedProtocolMessageType('Event', (_message.Message,), {
  'DESCRIPTOR' : _EVENT,
  '__module__' : 'coprocess_object_pb2'
  # @@protoc_insertion_point(class_scope:coprocess.Event)
  })
_sym_db.RegisterMessage(Event)

EventReply = _reflection.GeneratedProtocolMessageType('EventReply', (_message.Message,), {
  'DESCRIPTOR' : _EVENTREPLY,
  '__module__' : 'coprocess_object_pb2'
  # @@protoc_insertion_point(class_scope:coprocess.EventReply)
  })
_sym_db.RegisterMessage(EventReply)


_OBJECT_METADATAENTRY._options = None
_OBJECT_SPECENTRY._options = None

_DISPATCHER = _descriptor.ServiceDescriptor(
  name='Dispatcher',
  full_name='coprocess.Dispatcher',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=594,
  serialized_end=718,
  methods=[
  _descriptor.MethodDescriptor(
    name='Dispatch',
    full_name='coprocess.Dispatcher.Dispatch',
    index=0,
    containing_service=None,
    input_type=_OBJECT,
    output_type=_OBJECT,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='DispatchEvent',
    full_name='coprocess.Dispatcher.DispatchEvent',
    index=1,
    containing_service=None,
    input_type=_EVENT,
    output_type=_EVENTREPLY,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_DISPATCHER)

DESCRIPTOR.services_by_name['Dispatcher'] = _DISPATCHER

# @@protoc_insertion_point(module_scope)
