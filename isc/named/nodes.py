"""
isc.named.nodes
~~~~~~~~~~~~~~~
Domain dataclasses produced by the TransformationVisitor.

These are the final typed output of the pipeline:

  named.conf str
    → Lexer → tokens
    → Parser → Generic AST (Conf/Statement/Block/Negated)
    → SemanticVisitor → ValidatedConf (typed_ast.py)
    → TransformationVisitor → NamedConf (this file)

All fields default to None or empty list so the TransformationVisitor
can instantiate nodes with only the fields it resolved.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Union

from isc.named.typed_ast import (
    AddressMatchElement,
    TsigAlgorithmValue,
    AclRef, KeyRef,
)

__all__ = [
    "AddressMatchElement",
    "TsigAlgorithmValue",
    "AclStatement",
    "KeyStatement",
    "InetChannel",
    "UnixChannel",
    "NullDestination",
    "StderrDestination",
    "FileDestination",
    "SyslogDestination",
    "ChannelStatement",
    "CategoryStatement",
    "LoggingStatement",
    "ServerStatement",
    "UpdatePolicyRule",
    "ZoneStatement",
    "ViewStatement",
    "OptionsStatement",
    "TlsStatement",
    "HttpStatement",
    "StatisticsChannel",
    "TrustAnchorEntry",
    "DnssecKeySpec",
    "DnssecPolicyStatement",
    "IncludeStatement",
    "NamedConf",
]


@dataclass
class AclStatement:
    name:     str = ""
    elements: list[AddressMatchElement] = field(default_factory=list)


@dataclass
class KeyStatement:
    name:      str                       = ""
    algorithm: TsigAlgorithmValue | None = None
    secret:    str                       = ""


@dataclass
class InetChannel:
    address:   Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str] = None
    port:      int  | None = None
    allow:     list[AddressMatchElement] = field(default_factory=list)
    keys:      list[str]                 = field(default_factory=list)
    read_only: bool | None = None


@dataclass
class UnixChannel:
    path:      str        = ""
    perm:      int | None = None
    owner:     int | None = None
    group:     int | None = None
    keys:      list[str]  = field(default_factory=list)
    read_only: bool | None = None


@dataclass
class NullDestination:
    pass


@dataclass
class StderrDestination:
    pass


@dataclass
class FileDestination:
    path:     str        = ""
    versions: int | None = None
    size:     int | None = None
    suffix:   str | None = None


@dataclass
class SyslogDestination:
    facility: str | None = None


@dataclass
class ChannelStatement:
    name:           str = ""
    destination:    Union[
        NullDestination, StderrDestination,
        FileDestination, SyslogDestination, None,
    ] = None
    severity:       object = None
    print_time:     object = None
    print_severity: bool | None = None
    print_category: bool | None = None
    buffered:       bool | None = None


@dataclass
class CategoryStatement:
    name:     str       = ""
    channels: list[str] = field(default_factory=list)


@dataclass
class LoggingStatement:
    channels:   list[ChannelStatement]  = field(default_factory=list)
    categories: list[CategoryStatement] = field(default_factory=list)


@dataclass
class ServerStatement:
    address:         Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = None
    bogus:           bool | None = None
    edns:            bool | None = None
    edns_udp_size:   int  | None = None
    max_udp_size:    int  | None = None
    tcp_only:        bool | None = None
    transfers:       int  | None = None
    transfer_format: str  | None = None
    keys:            list[str]   = field(default_factory=list)
    request_expire:  bool | None = None
    request_ixfr:    bool | None = None


@dataclass
class UpdatePolicyRule:
    action:    str        = ""
    identity:  str        = ""
    matchtype: str        = ""
    name:      str | None = None
    rrtypes:   list[str]  = field(default_factory=list)


@dataclass
class ZoneStatement:
    name:                 str  = ""
    zone_class:           str | None = None
    type:                 str | None = None
    file:                 str | None = None
    masters:              list[AddressMatchElement] = field(default_factory=list)
    primaries:            list[AddressMatchElement] = field(default_factory=list)
    allow_query:          list[AddressMatchElement] = field(default_factory=list)
    allow_transfer:       list[AddressMatchElement] = field(default_factory=list)
    allow_update:         list[AddressMatchElement] = field(default_factory=list)
    allow_notify:         list[AddressMatchElement] = field(default_factory=list)
    also_notify:          list[AddressMatchElement] = field(default_factory=list)
    forwarders:           list[AddressMatchElement] = field(default_factory=list)
    forward:              str | None = None
    notify:               str | None = None
    key_directory:        str | None = None
    auto_dnssec:          str | None = None
    dnssec_policy:        str | None = None
    inline_signing:       bool | None = None
    update_policy:        Union[str, list[UpdatePolicyRule], None] = None
    check_names:          str | None = None
    zone_statistics:      bool | None = None
    serial_update_method: str | None = None


@dataclass
class ViewStatement:
    name:                 str        = ""
    view_class:           str | None = None
    zones:                list[ZoneStatement]       = field(default_factory=list)
    acls:                 list[AclStatement]        = field(default_factory=list)
    keys:                 list[KeyStatement]        = field(default_factory=list)
    match_clients:        list[AddressMatchElement] = field(default_factory=list)
    match_destinations:   list[AddressMatchElement] = field(default_factory=list)
    match_recursive_only: bool | None = None


@dataclass
class OptionsStatement:
    directory:              str  | None = None
    named_xfer:             str  | None = None
    pid_file:               str  | None = None
    dump_file:              str  | None = None
    statistics_file:        str  | None = None
    memstatistics_file:     str  | None = None
    session_keyfile:        str  | None = None
    bindkeys_file:          str  | None = None
    managed_keys_directory: str  | None = None
    listen_on:              list[AddressMatchElement] = field(default_factory=list)
    listen_on_v6:           list[AddressMatchElement] = field(default_factory=list)
    forwarders:             list[AddressMatchElement] = field(default_factory=list)
    forward:                str  | None = None
    recursion:              bool | None = None
    allow_query:            list[AddressMatchElement] = field(default_factory=list)
    allow_query_cache:      list[AddressMatchElement] = field(default_factory=list)
    allow_recursion:        list[AddressMatchElement] = field(default_factory=list)
    allow_transfer:         list[AddressMatchElement] = field(default_factory=list)
    blackhole:              list[AddressMatchElement] = field(default_factory=list)
    notify:                 str  | None = None
    also_notify:            list[AddressMatchElement] = field(default_factory=list)
    dnssec_validation:      str  | None = None
    version:                str  | None = None
    hostname:               str  | None = None
    server_id:              str  | None = None
    port:                   int  | None = None
    max_cache_size:         int  | None = None
    max_cache_ttl:          int  | None = None
    max_ncache_ttl:         int  | None = None
    transfers_in:           int  | None = None
    transfers_out:          int  | None = None
    transfer_format:        str  | None = None
    auth_nxdomain:          bool | None = None
    empty_zones_enable:     bool | None = None
    minimal_responses:      object     = None
    minimal_any:            bool | None = None
    tcp_clients:            int  | None = None
    recursive_clients:      int  | None = None
    resolver_query_timeout: int  | None = None
    interface_interval:     int  | None = None
    check_names:            str  | None = None


@dataclass
class TlsStatement:
    name:                  str        = ""
    key_file:              str | None = None
    cert_file:             str | None = None
    ca_file:               str | None = None
    dhparam_file:          str | None = None
    remote_hostname:       str | None = None
    protocols:             list[str]  = field(default_factory=list)
    ciphers:               str | None = None
    prefer_server_ciphers: bool | None = None
    session_tickets:       bool | None = None


@dataclass
class HttpStatement:
    name:                   str        = ""
    endpoints:              list[str]  = field(default_factory=list)
    listener_clients:       int | None = None
    streams_per_connection: int | None = None


@dataclass
class StatisticsChannel:
    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str] = None
    port:    int | None = None
    allow:   list[AddressMatchElement] = field(default_factory=list)


@dataclass
class TrustAnchorEntry:
    domain:      str = ""
    anchor_type: str = ""
    flags:       int = 0
    protocol:    int = 0
    algorithm:   int = 0
    key_data:    str = ""


@dataclass
class DnssecKeySpec:
    role:      str        = ""
    lifetime:  int | None = None
    algorithm: str | None = None


@dataclass
class DnssecPolicyStatement:
    name:                       str  = ""
    dnskey_ttl:                 int  | None = None
    keys:                       list[DnssecKeySpec] = field(default_factory=list)
    max_zone_ttl:               int  | None = None
    parent_ds_ttl:              int  | None = None
    publish_safety:             int  | None = None
    retire_safety:              int  | None = None
    signatures_refresh:         int  | None = None
    signatures_validity:        int  | None = None
    signatures_validity_dnskey: int  | None = None
    zone_propagation_delay:     int  | None = None


@dataclass
class IncludeStatement:
    path: str = ""


@dataclass
class NamedConf:
    options:             OptionsStatement | None               = None
    acls:                list[AclStatement]                    = field(default_factory=list)
    keys:                list[KeyStatement]                    = field(default_factory=list)
    zones:               list[ZoneStatement]                   = field(default_factory=list)
    views:               list[ViewStatement]                   = field(default_factory=list)
    controls:            list[Union[InetChannel, UnixChannel]] = field(default_factory=list)
    logging:             LoggingStatement | None               = None
    servers:             list[ServerStatement]                 = field(default_factory=list)
    tls:                 list[TlsStatement]                    = field(default_factory=list)
    http:                list[HttpStatement]                   = field(default_factory=list)
    statistics_channels: list[StatisticsChannel]               = field(default_factory=list)
    trusted_keys:        list[TrustAnchorEntry]                = field(default_factory=list)
    managed_keys:        list[TrustAnchorEntry]                = field(default_factory=list)
    trust_anchors:       list[TrustAnchorEntry]                = field(default_factory=list)
    dnssec_policies:     list[DnssecPolicyStatement]           = field(default_factory=list)
    includes:            list[IncludeStatement]                = field(default_factory=list)
