"""
isc.named.transformer
~~~~~~~~~~~~~~~~~~~~~
TransformationVisitor: walks a ValidatedConf tree and produces a NamedConf
domain object tree.

Responsibilities
----------------
  - Mapping validated statements to domain dataclasses via _NODE_MAP.
  - Cross-reference resolution: AclRef, KeyRef, TlsRef, ViewRef are
    verified against the definitions collected during the walk.
  - Structural folding: statements like controls that produce a list of
    channels are flattened into the appropriate NamedConf collection.

NOT responsible for
-------------------
  - Token-level validation — that is the SemanticVisitor's job.
  - Type coercion — values in ValidatedParam are already strongly typed.

Public API
----------
    from isc.named.transformer  import TransformationVisitor
    from isc.named.named_schema import NAMED_CONF
    from isc.named.parser       import parse
    from isc.named.semantic_visitor import SemanticVisitor

    conf      = parse(text)
    sv        = SemanticVisitor(NAMED_CONF)
    validated = sv.visit(conf)

    tv     = TransformationVisitor()
    result = tv.transform(validated)   # → NamedConf

    for err in sv.errors + tv.errors:
        print(err)

Extending
---------
To support a new statement add a method _transform_<keyword>(stmt) and
register it in _TRANSFORMERS. The method receives a ValidatedStatement and
returns the appropriate domain object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from isc.named.typed_ast import (
    ValidatedConf, ValidatedStatement, ValidatedParam,
    AddressMatchElement, TsigAlgorithmValue,
    AclRef, KeyRef, TlsRef, ViewRef,
)
from isc.named.nodes import (
    AclStatement, KeyStatement,
    InetChannel, UnixChannel,
    NullDestination, StderrDestination, FileDestination, SyslogDestination,
    ChannelStatement, CategoryStatement, LoggingStatement,
    ServerStatement, UpdatePolicyRule, ZoneStatement, ViewStatement,
    OptionsStatement, TlsStatement, HttpStatement,
    StatisticsChannel, TrustAnchorEntry,
    DnssecKeySpec, DnssecPolicyStatement,
    IncludeStatement, NamedConf,
)

__all__ = ["TransformationVisitor", "TransformationError", "Severity"]


# ---------------------------------------------------------------------------
# Error reporting
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TransformationVisitor
# ---------------------------------------------------------------------------

class TransformationVisitor:
    """
    Maps a ValidatedConf to a NamedConf by walking the validated statement
    tree and instantiating domain dataclasses.

    Cross-reference resolution is performed after the full tree is walked
    so that forward references (a reference appearing before its definition)
    are handled correctly.
    """

    def __init__(self) -> None:
        self.errors: list[TransformationError] = []
        # Registries for cross-reference resolution
        self._defs: dict[str, dict[str, Any]] = {
            "acl":  {},
            "key":  {},
            "tls":  {},
            "view": {},
        }
        self._pending_refs: list[tuple[Any, str, str]] = []
        # (ref_object, kind, context_description)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def transform(self, validated: ValidatedConf) -> NamedConf:
        """Transform a ValidatedConf into a NamedConf domain object."""
        conf = NamedConf()

        for stmt in validated.body:
            self._dispatch_top_level(stmt, conf)

        self._resolve_references()
        return conf

    # ------------------------------------------------------------------
    # Top-level dispatch
    # ------------------------------------------------------------------

    def _dispatch_top_level(
        self, stmt: ValidatedStatement, conf: NamedConf
    ) -> None:
        kw = stmt.keyword

        if kw == "options":
            conf.options = self._transform_options(stmt)

        elif kw == "acl":
            node = self._transform_acl(stmt)
            self._defs["acl"][node.name] = node
            conf.acls.append(node)

        elif kw == "key":
            node = self._transform_key(stmt)
            self._defs["key"][node.name] = node
            conf.keys.append(node)

        elif kw == "zone":
            conf.zones.append(self._transform_zone(stmt))

        elif kw == "view":
            node = self._transform_view(stmt)
            self._defs["view"][node.name] = node
            conf.views.append(node)

        elif kw == "controls":
            conf.controls.extend(self._transform_controls(stmt))

        elif kw == "logging":
            conf.logging = self._transform_logging(stmt)

        elif kw == "server":
            conf.servers.append(self._transform_server(stmt))

        elif kw == "tls":
            node = self._transform_tls(stmt)
            self._defs["tls"][node.name] = node
            conf.tls.append(node)

        elif kw == "http":
            conf.http.append(self._transform_http(stmt))

        elif kw == "statistics-channels":
            conf.statistics_channels.extend(
                self._transform_statistics_channels(stmt)
            )

        elif kw in ("trusted-keys", "managed-keys"):
            entries = self._transform_trust_entries(stmt)
            if kw == "trusted-keys":
                conf.trusted_keys.extend(entries)
            else:
                conf.managed_keys.extend(entries)

        elif kw == "trust-anchors":
            conf.trust_anchors.extend(self._transform_trust_entries(stmt))

        elif kw == "dnssec-policy":
            conf.dnssec_policies.append(self._transform_dnssec_policy(stmt))

        elif kw == "include":
            conf.includes.append(self._transform_include(stmt))

        else:
            self.errors.append(TransformationError(
                message=f"Unhandled top-level keyword '{kw}'",
                severity=Severity.WARNING,
                keyword=kw,
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _pv(self, stmt: ValidatedStatement, name: str, default: Any = None) -> Any:
        """Return the value of the named param, or default."""
        return stmt.param_value(name, default)

    def _body_pv(
        self, stmt: ValidatedStatement, keyword: str, param: str = "value",
        default: Any = None,
    ) -> Any:
        """Return a param value from the first body statement matching keyword."""
        child = stmt.body_first(keyword)
        if child is None:
            return default
        return child.param_value(param, default)

    def _body_list(
        self, stmt: ValidatedStatement, keyword: str, param: str = "elements",
    ) -> list:
        """Return the list param from the first body statement matching keyword."""
        child = stmt.body_first(keyword)
        if child is None:
            return []
        v = child.param_value(param)
        return v if isinstance(v, list) else []

    def _register_ref(self, ref: Any, kind: str, context: str) -> None:
        """Register a reference for deferred resolution."""
        if isinstance(ref, (AclRef, KeyRef, TlsRef, ViewRef)):
            self._pending_refs.append((ref, kind, context))

    def _err(self, message: str, keyword: str = "", severity: Severity = Severity.ERROR) -> None:
        self.errors.append(TransformationError(
            message=message, severity=severity, keyword=keyword,
        ))

    # ------------------------------------------------------------------
    # ACL
    # ------------------------------------------------------------------

    def _transform_acl(self, stmt: ValidatedStatement) -> AclStatement:
        elements = self._pv(stmt, "elements", [])
        return AclStatement(
            name=self._pv(stmt, "name", ""),
            elements=elements if isinstance(elements, list) else [],
        )

    # ------------------------------------------------------------------
    # Key
    # ------------------------------------------------------------------

    def _transform_key(self, stmt: ValidatedStatement) -> KeyStatement:
        def _val(kw: str) -> Any:
            child = stmt.body_first(kw)
            if child is None:
                return None
            return child.params[0].value if child.params else None

        alg = _val("algorithm")
        sec = _val("secret")
        return KeyStatement(
            name=self._pv(stmt, "name", ""),
            algorithm=alg if isinstance(alg, TsigAlgorithmValue) else None,
            secret=sec or "",
        )

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def _transform_controls(
        self, stmt: ValidatedStatement
    ) -> list[InetChannel | UnixChannel]:
        channels = self._pv(stmt, "controls", [])
        if not isinstance(channels, list):
            return []
        result = []
        for ch in channels:
            if isinstance(ch, ValidatedStatement):
                if ch.keyword == "inet":
                    result.append(self._transform_inet(ch))
                elif ch.keyword == "unix":
                    result.append(self._transform_unix(ch))
        return result

    def _transform_inet(self, stmt: ValidatedStatement) -> InetChannel:
        keys_raw = self._pv(stmt, "keys", [])
        keys = [str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])]
        allow_raw = self._pv(stmt, "allow", [])
        return InetChannel(
            address=self._pv(stmt, "address"),
            port=self._pv(stmt, "port"),
            allow=allow_raw if isinstance(allow_raw, list) else [],
            keys=keys,
            read_only=self._pv(stmt, "read_only"),
        )

    def _transform_unix(self, stmt: ValidatedStatement) -> UnixChannel:
        keys_raw = self._pv(stmt, "keys", [])
        keys = [str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])]
        return UnixChannel(
            path=self._pv(stmt, "path", ""),
            perm=self._pv(stmt, "perm"),
            owner=self._pv(stmt, "owner"),
            group=self._pv(stmt, "group"),
            keys=keys,
            read_only=self._pv(stmt, "read_only"),
        )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _transform_logging(self, stmt: ValidatedStatement) -> LoggingStatement:
        channels   = []
        categories = []

        for child in stmt.body:
            if child.keyword == "channel":
                channels.append(self._transform_channel(child))
            elif child.keyword == "category":
                categories.append(self._transform_category(child))

        return LoggingStatement(channels=channels, categories=categories)

    def _transform_channel(self, stmt: ValidatedStatement) -> ChannelStatement:
        def _val(kw: str) -> Any:
            child = stmt.body_first(kw)
            if child is None:
                return None
            v = child.param_value(kw)
            if v is None and child.params:
                v = child.params[0].value
            return v

        dest = None
        for child in stmt.body:
            if child.keyword == "null":
                dest = NullDestination()
            elif child.keyword == "stderr":
                dest = StderrDestination()
            elif child.keyword == "file":
                pv = lambda n: child.params[0].value if (
                    child.params and child.params[0].name == n
                ) else child.param_value(n)
                # path is first positional param
                path = child.params[0].value if child.params else ""
                versions_raw = child.param_value("versions")
                size_raw     = child.param_value("size")
                dest = FileDestination(
                    path=path if isinstance(path, str) else "",
                    versions=versions_raw if isinstance(versions_raw, int) else None,
                    size=size_raw if isinstance(size_raw, int) else None,
                    suffix=child.param_value("suffix"),
                )
            elif child.keyword == "syslog":
                facility = child.params[0].value if child.params else None
                dest = SyslogDestination(
                    facility=facility if isinstance(facility, str) else None
                )

        return ChannelStatement(
            name=self._pv(stmt, "name", ""),
            destination=dest,
            severity=_val("severity"),
            print_time=_val("print-time"),
            print_severity=_val("print-severity"),
            print_category=_val("print-category"),
            buffered=_val("buffered"),
        )

    def _transform_category(self, stmt: ValidatedStatement) -> CategoryStatement:
        channels_raw = self._pv(stmt, "channels", [])
        channels = [str(c) for c in (channels_raw if isinstance(channels_raw, list) else [])]
        return CategoryStatement(
            name=self._pv(stmt, "name", ""),
            channels=channels,
        )

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def _transform_server(self, stmt: ValidatedStatement) -> ServerStatement:
        def _val(kw: str) -> Any:
            child = stmt.body_first(kw)
            if child is None:
                return None
            v = child.param_value(kw)
            if v is None and child.params:
                v = child.params[0].value
            return v

        keys_child = stmt.body_first("keys")
        keys_raw   = keys_child.params[0].value if (
            keys_child and keys_child.params
        ) else []
        keys = [str(k) for k in (keys_raw if isinstance(keys_raw, list) else [])]

        return ServerStatement(
            address=self._pv(stmt, "address"),
            bogus=_val("bogus"),
            edns=_val("edns"),
            edns_udp_size=_val("edns-udp-size"),
            max_udp_size=_val("max-udp-size"),
            tcp_only=_val("tcp-only"),
            transfers=_val("transfers"),
            transfer_format=_val("transfer-format"),
            keys=keys,
            request_expire=_val("request-expire"),
            request_ixfr=_val("request-ixfr"),
        )

    # ------------------------------------------------------------------
    # Zone
    # ------------------------------------------------------------------

    def _transform_zone(self, stmt: ValidatedStatement) -> ZoneStatement:
        def _alist(keyword: str) -> list:
            child = stmt.body_first(keyword)
            if child is None:
                return []
            # param name matches the keyword exactly (hyphenated)
            v = child.param_value(keyword, [])
            if not isinstance(v, list):
                # fallback: try first param value
                v = child.params[0].value if child.params else []
            return v if isinstance(v, list) else []

        def _val(keyword: str) -> Any:
            child = stmt.body_first(keyword)
            if child is None:
                return None
            v = child.param_value(keyword)
            if v is None and child.params:
                v = child.params[0].value
            return v

        return ZoneStatement(
            name=self._pv(stmt, "name", ""),
            zone_class=self._pv(stmt, "zone_class"),
            type=_val("type"),
            file=_val("file"),
            masters=_alist("masters"),
            primaries=_alist("primaries"),
            allow_query=_alist("allow-query"),
            allow_transfer=_alist("allow-transfer"),
            allow_update=_alist("allow-update"),
            allow_notify=_alist("allow-notify"),
            also_notify=_alist("also-notify"),
            forwarders=_alist("forwarders"),
            forward=_val("forward"),
            notify=_val("notify"),
            key_directory=_val("key-directory"),
            auto_dnssec=_val("auto-dnssec"),
            dnssec_policy=_val("dnssec-policy"),
            inline_signing=_val("inline-signing"),
            check_names=_val("check-names"),
            zone_statistics=_val("zone-statistics"),
            serial_update_method=_val("serial-update-method"),
        )

    # ------------------------------------------------------------------
    # View
    # ------------------------------------------------------------------

    def _transform_view(self, stmt: ValidatedStatement) -> ViewStatement:
        zones = [self._transform_zone(s) for s in stmt.body if s.keyword == "zone"]
        acls  = [self._transform_acl(s)  for s in stmt.body if s.keyword == "acl"]
        keys  = [self._transform_key(s)  for s in stmt.body if s.keyword == "key"]

        for acl in acls:
            self._defs["acl"][acl.name] = acl
        for key in keys:
            self._defs["key"][key.name] = key

        def _alist(kw: str) -> list:
            child = stmt.body_first(kw)
            if child is None:
                return []
            v = child.param_value(kw, [])
            if not isinstance(v, list):
                v = child.params[0].value if child.params else []
            return v if isinstance(v, list) else []

        def _val(kw: str) -> Any:
            child = stmt.body_first(kw)
            if child is None:
                return None
            v = child.param_value(kw)
            if v is None and child.params:
                v = child.params[0].value
            return v

        return ViewStatement(
            name=self._pv(stmt, "name", ""),
            view_class=self._pv(stmt, "view_class"),
            zones=zones,
            acls=acls,
            keys=keys,
            match_clients=_alist("match-clients"),
            match_destinations=_alist("match-destinations"),
            match_recursive_only=_val("match-recursive-only"),
        )

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------

    def _transform_options(self, stmt: ValidatedStatement) -> OptionsStatement:
        def _val(keyword: str) -> Any:
            child = stmt.body_first(keyword)
            if child is None:
                return None
            v = child.param_value(keyword)
            if v is None and child.params:
                v = child.params[0].value
            return v

        def _alist(keyword: str) -> list:
            child = stmt.body_first(keyword)
            if child is None:
                return []
            v = child.param_value(keyword, [])
            if not isinstance(v, list):
                v = child.params[0].value if child.params else []
            return v if isinstance(v, list) else []

        return OptionsStatement(
            directory=_val("directory"),
            named_xfer=_val("named-xfer"),
            pid_file=_val("pid-file"),
            dump_file=_val("dump-file"),
            statistics_file=_val("statistics-file"),
            memstatistics_file=_val("memstatistics-file"),
            session_keyfile=_val("session-keyfile"),
            bindkeys_file=_val("bindkeys-file"),
            managed_keys_directory=_val("managed-keys-directory"),
            listen_on=_alist("listen-on"),
            listen_on_v6=_alist("listen-on-v6"),
            forwarders=_alist("forwarders"),
            forward=_val("forward"),
            recursion=_val("recursion"),
            allow_query=_alist("allow-query"),
            allow_query_cache=_alist("allow-query-cache"),
            allow_recursion=_alist("allow-recursion"),
            allow_transfer=_alist("allow-transfer"),
            blackhole=_alist("blackhole"),
            notify=_val("notify"),
            also_notify=_alist("also-notify"),
            dnssec_validation=_val("dnssec-validation"),
            version=_val("version"),
            hostname=_val("hostname"),
            server_id=_val("server-id"),
            port=_val("port"),
            max_cache_size=_val("max-cache-size"),
            max_cache_ttl=_val("max-cache-ttl"),
            max_ncache_ttl=_val("max-ncache-ttl"),
            transfers_in=_val("transfers-in"),
            transfers_out=_val("transfers-out"),
            transfer_format=_val("transfer-format"),
            auth_nxdomain=_val("auth-nxdomain"),
            empty_zones_enable=_val("empty-zones-enable"),
            minimal_responses=_val("minimal-responses"),
            minimal_any=_val("minimal-any"),
            tcp_clients=_val("tcp-clients"),
            recursive_clients=_val("recursive-clients"),
            resolver_query_timeout=_val("resolver-query-timeout"),
            interface_interval=_val("interface-interval"),
            check_names=_val("check-names"),
        )

    # ------------------------------------------------------------------
    # TLS
    # ------------------------------------------------------------------

    def _transform_tls(self, stmt: ValidatedStatement) -> TlsStatement:
        def _val(kw: str) -> Any:
            child = stmt.body_first(kw)
            if child is None:
                return None
            v = child.param_value(kw)
            if v is None and child.params:
                v = child.params[0].value
            return v

        protocols_child = stmt.body_first("protocols")
        protocols = []
        if protocols_child and protocols_child.params:
            raw = protocols_child.params[0].value
            protocols = raw if isinstance(raw, list) else []

        return TlsStatement(
            name=self._pv(stmt, "name", ""),
            key_file=_val("key-file"),
            cert_file=_val("cert-file"),
            ca_file=_val("ca-file"),
            dhparam_file=_val("dhparam-file"),
            remote_hostname=_val("remote-hostname"),
            protocols=protocols,
            ciphers=_val("ciphers"),
            prefer_server_ciphers=_val("prefer-server-ciphers"),
            session_tickets=_val("session-tickets"),
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _transform_http(self, stmt: ValidatedStatement) -> HttpStatement:
        return HttpStatement(
            name=self._pv(stmt, "name", ""),
            endpoints=self._body_pv(stmt, "endpoints", "endpoints") or [],
            listener_clients=self._body_pv(
                stmt, "listener-clients", "listener-clients"
            ),
            streams_per_connection=self._body_pv(
                stmt, "streams-per-connection", "streams-per-connection"
            ),
        )

    # ------------------------------------------------------------------
    # Statistics channels
    # ------------------------------------------------------------------

    def _transform_statistics_channels(
        self, stmt: ValidatedStatement
    ) -> list[StatisticsChannel]:
        channels_raw = self._pv(stmt, "statistics_channels", [])
        if not isinstance(channels_raw, list):
            return []
        result = []
        for ch in channels_raw:
            if isinstance(ch, ValidatedStatement) and ch.keyword == "inet":
                allow_raw = ch.param_value("allow", [])
                result.append(StatisticsChannel(
                    address=ch.param_value("address"),
                    port=ch.param_value("port"),
                    allow=allow_raw if isinstance(allow_raw, list) else [],
                ))
        return result

    # ------------------------------------------------------------------
    # Trust anchors
    # ------------------------------------------------------------------

    def _transform_trust_entries(
        self, stmt: ValidatedStatement
    ) -> list[TrustAnchorEntry]:
        raw = (
            self._pv(stmt, "trusted_keys")
            or self._pv(stmt, "managed_keys")
            or self._pv(stmt, "trust_anchors")
            or []
        )
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

    def _transform_dnssec_policy(
        self, stmt: ValidatedStatement
    ) -> DnssecPolicyStatement:
        keys_raw = self._body_pv(stmt, "keys", "keys", [])
        keys = []
        if isinstance(keys_raw, list):
            for k in keys_raw:
                if isinstance(k, ValidatedStatement):
                    keys.append(DnssecKeySpec(
                        role=k.keyword,
                        lifetime=k.param_value("lifetime"),
                        algorithm=k.param_value("algorithm"),
                    ))

        return DnssecPolicyStatement(
            name=self._pv(stmt, "name", ""),
            dnskey_ttl=self._body_pv(stmt, "dnskey-ttl", "dnskey-ttl"),
            keys=keys,
            max_zone_ttl=self._body_pv(stmt, "max-zone-ttl", "max-zone-ttl"),
            parent_ds_ttl=self._body_pv(stmt, "parent-ds-ttl", "parent-ds-ttl"),
            publish_safety=self._body_pv(stmt, "publish-safety", "publish-safety"),
            retire_safety=self._body_pv(stmt, "retire-safety", "retire-safety"),
            signatures_refresh=self._body_pv(
                stmt, "signatures-refresh", "signatures-refresh"
            ),
            signatures_validity=self._body_pv(
                stmt, "signatures-validity", "signatures-validity"
            ),
            signatures_validity_dnskey=self._body_pv(
                stmt, "signatures-validity-dnskey", "signatures-validity-dnskey"
            ),
            zone_propagation_delay=self._body_pv(
                stmt, "zone-propagation-delay", "zone-propagation-delay"
            ),
        )

    # ------------------------------------------------------------------
    # Include
    # ------------------------------------------------------------------

    def _transform_include(self, stmt: ValidatedStatement) -> IncludeStatement:
        return IncludeStatement(path=self._pv(stmt, "path", ""))

    # ------------------------------------------------------------------
    # Cross-reference resolution
    # ------------------------------------------------------------------

    def _resolve_references(self) -> None:
        """Verify all collected references against the definitions registry."""
        _builtin_acls = frozenset({"any", "none", "localhost", "localnets"})

        for ref, kind, context in self._pending_refs:
            name = ref.name

            if kind == "acl" and name in _builtin_acls:
                continue

            if name not in self._defs.get(kind, {}):
                self._err(
                    f"{kind} '{name}' is referenced but never defined"
                    + (f" (in {context})" if context else ""),
                    keyword=kind,
                    severity=Severity.ERROR,
                )
