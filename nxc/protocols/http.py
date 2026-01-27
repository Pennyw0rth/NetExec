# Entry-point file for the HTTP protocol.
# ProtocolLoader discovers protocols by scanning nxc/protocols/*.py

from nxc.protocols.http.http import http  # class with proto_flow/plaintext_login/etc
from nxc.protocols.http.proto_args import proto_args  # function used by cli

protocol_object = http

__all__ = ["proto_args", "protocol_object"]
