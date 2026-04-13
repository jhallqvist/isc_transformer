"""
isc.named.transformer
~~~~~~~~~~~~~~~~~~~~~
TransformationVisitor: maps a ValidatedConf to a NamedConf domain object.

Responsibilities
----------------
  - Mapping validated statements to domain dataclasses.
  - Cross-reference resolution: AclRef, KeyRef, TlsRef, ViewRef verified
    against definitions collected during the walk.
  - Structural folding: controls channels flattened into NamedConf.controls.

NOT responsible for
-------------------
  - Token-level validation or type coercion — those are done by SemanticVisitor.

Public API
----------
    from isc.named.transformer      import TransformationVisitor
    from isc.named.semantic_visitor import SemanticVisitor
    from isc.named.named_schema     import NAMED_CONF
    from isc.named.parser           import parse

    conf      = parse(text)
    sv        = SemanticVisitor(NAMED_CONF)
    validated = sv.visit(conf)
    tv        = TransformationVisitor()
    result    = tv.transform(validated)   # → NamedConf

    for err in sv.errors + tv.errors:
        print(err)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from isc.named.typed_ast import (
    ValidatedConf, ValidatedStatement,
    AddressMatchElement, TsigAlgorithmValue,
    AclRef, KeyRef, TlsRef, ViewRef,
)
from isc.named.nodes import (
    AclStatement, KeyStatement,
    InetChannel, UnixChannel,
    NullDestination, StderrDestination, FileDestination, SyslogDestination,
    ChannelStatement, CategoryStatement, LoggingStatement,
    ServerStatement, ZoneStatement, ViewStatement,
    OptionsStatement, TlsStatement, HttpStatement,
    StatisticsChannel, TrustAnchorEntry,
    DnssecKeySpec, DnssecPolicyStatement,
    IncludeStatement, NamedConf,
)

__all__ = ["TransformationVisitor", "TransformationError", "Severity"]


class Severity(str, Enum):
    ERROR   = "ERROR"
    WARNING = "WARNING"
    INFO    = "INFO"


@dataclass
class TransformationError:
    message:  str
    severity: Severity = Severity.ERROR
    keyword:  str = ""

    def __str__(self) -> str:
        ctx = f" [{self.keyword}]" if self.keyword else ""
        return f"{self.severity}{ctx}: {self.message}"


_BUILTIN_ACLS = frozenset({"any", "none", "localhost", "localnets"})


class TransformationVisitor:
    """
    Maps a ValidatedConf to a NamedConf.

    Each _transform_* method receives a ValidatedStatement and uses the
    ValidatedStatement lookup API (param_value, body_value, body_elements)
    to extract values without any positional indexing.
    """

    def __init__(self) -> None:
        self.errors: list[TransformationError] = []
        self._defs: dict[str, dict[str, Any]] = {
            "acl": {}, "key": {}, "tls": {}, "view": {},
        }
        self._pending_refs: list[tuple[Any, str]] = []

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def transform(self, validated: ValidatedConf) -> NamedConf:
        conf = NamedConf()
        for stmt in validated.body:
            self._dispatch(stmt, conf)
        # Collect all reference objects from the entire validated tree
        self._walk_refs(validated)
        self._resolve_references()
        return conf

    def _walk_refs(self, validated: ValidatedConf) -> None:
        """Walk every ValidatedParam in the tree and register ref objects."""
        for stmt in validated.body:
            self._walk_stmt_refs(stmt)

    def _walk_stmt_refs(self, stmt: ValidatedStatement) -> None:
        for param in stmt.params:
            self._collect_refs(param.value)
        for child in stmt.body:
            self._walk_stmt_refs(child)

    def _dispatch(self, stmt: ValidatedStatement, conf: NamedConf) -> None:
        kw = stmt.keyword
        if   kw == "options":            conf.options = self._transform_options(stmt)
        elif kw == "acl":                self._register_and_append(conf.acls, "acl", self._transform_acl(stmt))
        elif kw == "key":                self._register_and_append(conf.keys, "key", self._transform_key(stmt))
        elif kw == "zone":               conf.zones.append(self._transform_zone(stmt))
        elif kw == "view":               self._register_and_append(conf.views, "view", self._transform_view(stmt))
        elif kw == "controls":           conf.controls.extend(self._transform_controls(stmt))
        elif kw == "logging":            conf.logging = self._transform_logging(stmt)
        elif kw == "server":             conf.servers.append(self._transform_server(stmt))
        elif kw == "tls":                self._register_and_append(conf.tls, "tls", self._transform_tls(stmt))
        elif kw == "http":               conf.http.append(self._transform_http(stmt))
        elif kw == "statistics-channels":conf.statistics_channels.extend(self._transform_stats_channels(stmt))
        elif kw == "trusted-keys":       conf.trusted_keys.extend(self._transform_trust_entries(stmt, "trusted_keys"))
        elif kw == "managed-keys":       conf.managed_keys.extend(self._transform_trust_entries(stmt, "managed_keys"))
        elif kw == "trust-anchors":      conf.trust_anchors.extend(self._transform_trust_entries(stmt, "trust_anchors"))
        elif kw == "dnssec-policy":      conf.dnssec_policies.append(self._transform_dnssec_policy(stmt))
        elif kw == "include":            conf.includes.append(IncludeStatement(path=stmt.param_value("path", "")))
        else: self._err(f"Unhandled keyword '{kw}'", kw, Severity.WARNING)

    def _register_and_append(self, collection: list, kind: str, node: Any) -> None:
        if hasattr(node, "name"):
            self._defs[kind][node.name] = node
        collection.append(node)

    # ------------------------------------------------------------------
    # ACL
    # ------------------------------------------------------------------

    def _transform_acl(self, stmt: ValidatedStatement) -> AclStatement:
        return AclStatement(
            name=stmt.param_value("name", ""),
            elements=stmt.param_value("elements", []),
        )

    # ------------------------------------------------------------------
    # Key
    # ------------------------------------------------------------------

    def _transform_key(self, stmt: ValidatedStatement) -> KeyStatement:
        alg = stmt.body_value("algorithm", "algorithm")
        sec = stmt.body_value("secret",    "secret", "")
        return KeyStatement(
            name=stmt.param_value("name", ""),
            algorithm=alg if isinstance(alg, TsigAlgorithmValue) else None,
            secret=sec or "",
        )

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def _transform_controls(self, stmt: ValidatedStatement) -> list:
        raw = stmt.param_value("controls", [])
        if not isinstance(raw, list):
            return []
        result = []
        for ch in raw:
            if isinstance(ch, ValidatedStatement):
                if ch.keyword == "inet":
                    result.append(self._transform_inet(ch))
                elif ch.keyword == "unix":
                    result.append(self._transform_unix(ch))
        return result

    def _transform_inet(self, stmt: ValidatedStatement) -> InetChannel:
        keys_raw = stmt.param_value("keys", [])
        return InetChannel(
            address=stmt.param_value("address"),
            port=stmt.param_value("port"),
            allow=stmt.param_value("allow", []),
            keys=[str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])],
            read_only=stmt.param_value("read-only"),
        )

    def _transform_unix(self, stmt: ValidatedStatement) -> UnixChannel:
        keys_raw = stmt.param_value("keys", [])
        return UnixChannel(
            path=stmt.param_value("path", ""),
            perm=stmt.param_value("perm"),
            owner=stmt.param_value("owner"),
            group=stmt.param_value("group"),
            keys=[str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])],
            read_only=stmt.param_value("read-only"),
        )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _transform_logging(self, stmt: ValidatedStatement) -> LoggingStatement:
        return LoggingStatement(
            channels=[self._transform_channel(s)
                      for s in stmt.body if s.keyword == "channel"],
            categories=[self._transform_category(s)
                        for s in stmt.body if s.keyword == "category"],
        )

    def _transform_channel(self, stmt: ValidatedStatement) -> ChannelStatement:
        dest = None
        for child in stmt.body:
            kw = child.keyword
            if   kw == "null":   dest = NullDestination()
            elif kw == "stderr": dest = StderrDestination()
            elif kw == "syslog": dest = SyslogDestination(
                facility=child.params[0].value if child.params else None)
            elif kw == "file":
                dest = FileDestination(
                    path=child.param_value("path", ""),
                    versions=child.param_value("versions"),
                    size=child.param_value("size"),
                    suffix=child.param_value("suffix"),
                )
        return ChannelStatement(
            name=stmt.param_value("name", ""),
            destination=dest,
            severity=stmt.body_value("severity",       "severity"),
            print_time=stmt.body_value("print-time",    "print-time"),
            print_severity=stmt.body_value("print-severity", "print-severity"),
            print_category=stmt.body_value("print-category", "print-category"),
            buffered=stmt.body_value("buffered",        "buffered"),
        )

    def _transform_category(self, stmt: ValidatedStatement) -> CategoryStatement:
        channels_raw = stmt.param_value("channels", [])
        return CategoryStatement(
            name=stmt.param_value("name", ""),
            channels=[str(c) for c in (channels_raw if isinstance(channels_raw, list) else [])],
        )

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def _transform_server(self, stmt: ValidatedStatement) -> ServerStatement:
        keys_raw = stmt.body_value("keys", "keys", [])
        return ServerStatement(
            address=stmt.param_value("address"),
            bogus=stmt.body_value("bogus",           "bogus"),
            edns=stmt.body_value("edns",             "edns"),
            edns_udp_size=stmt.body_value("edns-udp-size",   "edns-udp-size"),
            max_udp_size=stmt.body_value("max-udp-size",    "max-udp-size"),
            tcp_only=stmt.body_value("tcp-only",        "tcp-only"),
            transfers=stmt.body_value("transfers",       "transfers"),
            transfer_format=stmt.body_value("transfer-format", "transfer-format"),
            keys=[str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])],
            request_expire=stmt.body_value("request-expire",  "request-expire"),
            request_ixfr=stmt.body_value("request-ixfr",    "request-ixfr"),
        )

    # ------------------------------------------------------------------
    # Zone
    # ------------------------------------------------------------------

    def _transform_zone(self, stmt: ValidatedStatement) -> ZoneStatement:
        return ZoneStatement(
            name=stmt.param_value("name", ""),
            zone_class=stmt.param_value("zone_class"),
            type=stmt.body_value("type",           "type"),
            file=stmt.body_value("file",           "file"),
            masters=stmt.body_elements("masters"),
            primaries=stmt.body_elements("primaries"),
            allow_query=stmt.body_elements("allow-query"),
            allow_transfer=stmt.body_elements("allow-transfer"),
            allow_update=stmt.body_elements("allow-update"),
            allow_notify=stmt.body_elements("allow-notify"),
            also_notify=stmt.body_elements("also-notify"),
            forwarders=stmt.body_elements("forwarders"),
            forward=stmt.body_value("forward",        "forward"),
            notify=stmt.body_value("notify",          "notify"),
            key_directory=stmt.body_value("key-directory",  "key-directory"),
            auto_dnssec=stmt.body_value("auto-dnssec",    "auto-dnssec"),
            dnssec_policy=stmt.body_value("dnssec-policy",  "dnssec-policy"),
            inline_signing=stmt.body_value("inline-signing", "inline-signing"),
            check_names=stmt.body_value("check-names",    "check-names"),
            zone_statistics=stmt.body_value("zone-statistics","zone-statistics"),
            serial_update_method=stmt.body_value("serial-update-method",
                                                 "serial-update-method"),
        )

    # ------------------------------------------------------------------
    # View
    # ------------------------------------------------------------------

    def _transform_view(self, stmt: ValidatedStatement) -> ViewStatement:
        zones = [self._transform_zone(s) for s in stmt.body if s.keyword == "zone"]
        acls  = [self._transform_acl(s)  for s in stmt.body if s.keyword == "acl"]
        keys  = [self._transform_key(s)  for s in stmt.body if s.keyword == "key"]
        for acl in acls: self._defs["acl"][acl.name] = acl
        for key in keys: self._defs["key"][key.name] = key
        return ViewStatement(
            name=stmt.param_value("name", ""),
            view_class=stmt.param_value("view_class"),
            zones=zones,
            acls=acls,
            keys=keys,
            match_clients=stmt.body_elements("match-clients"),
            match_destinations=stmt.body_elements("match-destinations"),
            match_recursive_only=stmt.body_value(
                "match-recursive-only", "match-recursive-only"),
        )

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------

    def _transform_options(self, stmt: ValidatedStatement) -> OptionsStatement:
        bv  = stmt.body_value
        be  = stmt.body_elements
        return OptionsStatement(
            directory=bv("directory",              "directory"),
            named_xfer=bv("named-xfer",             "named-xfer"),
            pid_file=bv("pid-file",               "pid-file"),
            dump_file=bv("dump-file",              "dump-file"),
            statistics_file=bv("statistics-file",        "statistics-file"),
            memstatistics_file=bv("memstatistics-file",     "memstatistics-file"),
            session_keyfile=bv("session-keyfile",        "session-keyfile"),
            bindkeys_file=bv("bindkeys-file",          "bindkeys-file"),
            managed_keys_directory=bv("managed-keys-directory","managed-keys-directory"),
            listen_on=be("listen-on"),
            listen_on_v6=be("listen-on-v6"),
            forwarders=be("forwarders"),
            forward=bv("forward",             "forward"),
            recursion=bv("recursion",           "recursion"),
            allow_query=be("allow-query"),
            allow_query_cache=be("allow-query-cache"),
            allow_recursion=be("allow-recursion"),
            allow_transfer=be("allow-transfer"),
            blackhole=be("blackhole"),
            notify=bv("notify",              "notify"),
            also_notify=be("also-notify"),
            dnssec_validation=bv("dnssec-validation",  "dnssec-validation"),
            version=bv("version",             "version"),
            hostname=bv("hostname",            "hostname"),
            server_id=bv("server-id",           "server-id"),
            port=bv("port",                "port"),
            max_cache_size=bv("max-cache-size",     "max-cache-size"),
            max_cache_ttl=bv("max-cache-ttl",      "max-cache-ttl"),
            max_ncache_ttl=bv("max-ncache-ttl",     "max-ncache-ttl"),
            transfers_in=bv("transfers-in",        "transfers-in"),
            transfers_out=bv("transfers-out",       "transfers-out"),
            transfer_format=bv("transfer-format",    "transfer-format"),
            auth_nxdomain=bv("auth-nxdomain",      "auth-nxdomain"),
            empty_zones_enable=bv("empty-zones-enable", "empty-zones-enable"),
            minimal_responses=bv("minimal-responses",  "minimal-responses"),
            minimal_any=bv("minimal-any",          "minimal-any"),
            tcp_clients=bv("tcp-clients",          "tcp-clients"),
            recursive_clients=bv("recursive-clients",    "recursive-clients"),
            resolver_query_timeout=bv("resolver-query-timeout","resolver-query-timeout"),
            interface_interval=bv("interface-interval",   "interface-interval"),
            check_names=bv("check-names",          "check-names"),
        )

    # ------------------------------------------------------------------
    # TLS
    # ------------------------------------------------------------------

    def _transform_tls(self, stmt: ValidatedStatement) -> TlsStatement:
        bv = stmt.body_value
        protocols_raw = bv("protocols", "protocols", [])
        return TlsStatement(
            name=stmt.param_value("name", ""),
            key_file=bv("key-file",              "key-file"),
            cert_file=bv("cert-file",             "cert-file"),
            ca_file=bv("ca-file",               "ca-file"),
            dhparam_file=bv("dhparam-file",          "dhparam-file"),
            remote_hostname=bv("remote-hostname",       "remote-hostname"),
            protocols=protocols_raw if isinstance(protocols_raw, list) else [],
            ciphers=bv("ciphers",               "ciphers"),
            prefer_server_ciphers=bv("prefer-server-ciphers","prefer-server-ciphers"),
            session_tickets=bv("session-tickets",       "session-tickets"),
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _transform_http(self, stmt: ValidatedStatement) -> HttpStatement:
        bv = stmt.body_value
        endpoints_raw = bv("endpoints", "endpoints", [])
        return HttpStatement(
            name=stmt.param_value("name", ""),
            endpoints=endpoints_raw if isinstance(endpoints_raw, list) else [],
            listener_clients=bv("listener-clients",       "listener-clients"),
            streams_per_connection=bv("streams-per-connection","streams-per-connection"),
        )

    # ------------------------------------------------------------------
    # Statistics channels
    # ------------------------------------------------------------------

    def _transform_stats_channels(self, stmt: ValidatedStatement) -> list:
        raw = stmt.param_value("statistics_channels", [])
        if not isinstance(raw, list):
            return []
        result = []
        for ch in raw:
            if isinstance(ch, ValidatedStatement) and ch.keyword == "inet":
                result.append(StatisticsChannel(
                    address=ch.param_value("address"),
                    port=ch.param_value("port"),
                    allow=ch.param_value("allow", []),
                ))
        return result

    # ------------------------------------------------------------------
    # Trust anchors
    # ------------------------------------------------------------------

    def _transform_trust_entries(
        self, stmt: ValidatedStatement, param: str
    ) -> list[TrustAnchorEntry]:
        raw = stmt.param_value(param, [])
        if not isinstance(raw, list):
            return []
        result = []
        for entry in raw:
            if isinstance(entry, ValidatedStatement):
                result.append(TrustAnchorEntry(
                    domain=entry.param_value("domain", ""),
                    anchor_type=entry.param_value("anchor_type", ""),
                    flags=entry.param_value("flags", 0),
                    protocol=entry.param_value("protocol", 0),
                    algorithm=entry.param_value("algorithm", 0),
                    key_data=entry.param_value("key_data", ""),
                ))
        return result

    # ------------------------------------------------------------------
    # DNSSEC policy
    # ------------------------------------------------------------------

    def _transform_dnssec_policy(self, stmt: ValidatedStatement) -> DnssecPolicyStatement:
        keys_raw = stmt.body_value("keys", "keys", [])
        keys = []
        if isinstance(keys_raw, list):
            for k in keys_raw:
                if isinstance(k, ValidatedStatement):
                    keys.append(DnssecKeySpec(
                        role=k.keyword,
                        lifetime=k.param_value("lifetime"),
                        algorithm=k.param_value("algorithm"),
                    ))
        bv = stmt.body_value
        return DnssecPolicyStatement(
            name=stmt.param_value("name", ""),
            dnskey_ttl=bv("dnskey-ttl",   "dnskey-ttl"),
            keys=keys,
            max_zone_ttl=bv("max-zone-ttl",             "max-zone-ttl"),
            parent_ds_ttl=bv("parent-ds-ttl",            "parent-ds-ttl"),
            publish_safety=bv("publish-safety",           "publish-safety"),
            retire_safety=bv("retire-safety",            "retire-safety"),
            signatures_refresh=bv("signatures-refresh",       "signatures-refresh"),
            signatures_validity=bv("signatures-validity",      "signatures-validity"),
            signatures_validity_dnskey=bv("signatures-validity-dnskey",
                                          "signatures-validity-dnskey"),
            zone_propagation_delay=bv("zone-propagation-delay", "zone-propagation-delay"),
        )

    # ------------------------------------------------------------------
    # Cross-reference resolution
    # ------------------------------------------------------------------

    def _resolve_references(self) -> None:
        """Verify all collected references against the definitions registry."""
        for ref, kind in self._pending_refs:
            if kind == "acl" and ref.name in _BUILTIN_ACLS:
                continue
            if ref.name not in self._defs.get(kind, {}):
                self._err(
                    f"{kind} '{ref.name}' is referenced but never defined",
                    keyword=kind,
                )

    def _collect_refs(self, value: Any) -> None:
        """
        Recursively walk a coerced value and register any reference objects
        into _pending_refs for deferred resolution.
        """
        if isinstance(value, AclRef):
            self._pending_refs.append((value, "acl"))
        elif isinstance(value, KeyRef):
            self._pending_refs.append((value, "key"))
        elif isinstance(value, TlsRef):
            self._pending_refs.append((value, "tls"))
        elif isinstance(value, ViewRef):
            self._pending_refs.append((value, "view"))
        elif isinstance(value, list):
            for item in value:
                self._collect_refs(item)
        elif isinstance(value, AddressMatchElement):
            self._collect_refs(value.value)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _err(
        self, message: str, keyword: str = "", severity: Severity = Severity.ERROR
    ) -> None:
        self.errors.append(TransformationError(
            message=message, severity=severity, keyword=keyword,
        ))
