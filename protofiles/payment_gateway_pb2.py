# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: payment_gateway.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'payment_gateway.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15payment_gateway.proto\"j\n\x19\x43lientRegistrationRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x10\n\x08password\x18\x02 \x01(\t\x12\x11\n\tbank_name\x18\x03 \x01(\t\x12\x16\n\x0e\x61\x63\x63ount_number\x18\x04 \x01(\t\">\n\x1a\x43lientRegistrationResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"1\n\x0b\x41uthRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x10\n\x08password\x18\x02 \x01(\t\"4\n\x0c\x41uthResponse\x12\x15\n\rauthenticated\x18\x01 \x01(\x08\x12\r\n\x05token\x18\x02 \x01(\t\"l\n\x0ePaymentRequest\x12\r\n\x05token\x18\x01 \x01(\t\x12\x14\n\x0c\x66rom_account\x18\x02 \x01(\t\x12\x12\n\nto_account\x18\x03 \x01(\t\x12\x11\n\tbank_name\x18\x04 \x01(\t\x12\x0e\n\x06\x61mount\x18\x05 \x01(\x01\"3\n\x0fPaymentResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"7\n\x0e\x42\x61lanceRequest\x12\r\n\x05token\x18\x01 \x01(\t\x12\x16\n\x0e\x61\x63\x63ount_number\x18\x02 \x01(\t\"\"\n\x0f\x42\x61lanceResponse\x12\x0f\n\x07\x62\x61lance\x18\x01 \x01(\x01\x32\xf6\x01\n\x0ePaymentGateway\x12I\n\x0eRegisterClient\x12\x1a.ClientRegistrationRequest\x1a\x1b.ClientRegistrationResponse\x12\x31\n\x12\x41uthenticateClient\x12\x0c.AuthRequest\x1a\r.AuthResponse\x12\x33\n\x0eProcessPayment\x12\x0f.PaymentRequest\x1a\x10.PaymentResponse\x12\x31\n\x0c\x43heckBalance\x12\x0f.BalanceRequest\x1a\x10.BalanceResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'payment_gateway_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_CLIENTREGISTRATIONREQUEST']._serialized_start=25
  _globals['_CLIENTREGISTRATIONREQUEST']._serialized_end=131
  _globals['_CLIENTREGISTRATIONRESPONSE']._serialized_start=133
  _globals['_CLIENTREGISTRATIONRESPONSE']._serialized_end=195
  _globals['_AUTHREQUEST']._serialized_start=197
  _globals['_AUTHREQUEST']._serialized_end=246
  _globals['_AUTHRESPONSE']._serialized_start=248
  _globals['_AUTHRESPONSE']._serialized_end=300
  _globals['_PAYMENTREQUEST']._serialized_start=302
  _globals['_PAYMENTREQUEST']._serialized_end=410
  _globals['_PAYMENTRESPONSE']._serialized_start=412
  _globals['_PAYMENTRESPONSE']._serialized_end=463
  _globals['_BALANCEREQUEST']._serialized_start=465
  _globals['_BALANCEREQUEST']._serialized_end=520
  _globals['_BALANCERESPONSE']._serialized_start=522
  _globals['_BALANCERESPONSE']._serialized_end=556
  _globals['_PAYMENTGATEWAY']._serialized_start=559
  _globals['_PAYMENTGATEWAY']._serialized_end=805
# @@protoc_insertion_point(module_scope)
