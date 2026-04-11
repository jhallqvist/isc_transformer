"""
isc.named.named_schema
~~~~~~~~~~~~~~~~~~~~~~
Complete DSL schema for ISC BIND named.conf.

Each top-level statement is defined as a StatementDef using the DSL
types from isc.named.dsl. The root NAMED_CONF Context wires them
together with their cardinality.

Coverage
--------
  options         global server options (common subset)
  acl             address-match list alias
  key             TSIG/TKEY shared secret
  zone            zone declaration
  view            view declaration
  controls        RNDC control channels (inet, unix)
  logging         channels and categories
  server          per-remote-server settings
  tls             TLS context (BIND 9.18+)
  http            HTTP endpoint (BIND 9.18+)
  statistics-channels  HTTP statistics endpoint
  trusted-keys    explicitly trusted DNSSEC keys (deprecated)
  managed-keys    RFC 5011 managed keys (deprecated)
  trust-anchors   RFC 5011 trust anchors
  dnssec-policy   DNSSEC signing policy
  include         include another file

Extending
---------
Add a StatementDef and wire it into NAMED_CONF (or a sub-Context).
The visitor requires no changes — it dispatches purely on DSL structure.
"""

from __future__ import annotations

from isc.named.dsl import (
    Arg, Keyword, Optional, Negatable, Wildcard, Deprecated,
    Multiple, OneOf, ExclusiveOf, Variadic, ListOf, Context,
    StatementDef,
    IpAddressType, IpPrefixType, BooleanType, Integer, FixedPoint,
    Percentage, Size, StringType, EnumType, Duration, RrTypeList,
    TsigAlgorithm, Base64, Unlimited,
    AclReference, KeyReference, TlsReference, ViewReference,
)


__all__ = ["NAMED_CONF"]


# ---------------------------------------------------------------------------
# Shared constructs
# ---------------------------------------------------------------------------

# Recursive address-match element.
# Defined before use — Python resolves the name at walk time, not definition
# time, so the forward reference in ListOf(...) is safe.
ADDRESS_MATCH_ELEMENT = Negatable(Arg("value",
    IpAddressType(),
    IpPrefixType(),
    AclReference(),
    KeyReference(),
    ListOf(None),   # recursive — patched below
))

# Patch the recursive ListOf now that ADDRESS_MATCH_ELEMENT is defined
from dataclasses import replace as _replace
_recursive_list = ListOf(ADDRESS_MATCH_ELEMENT)
ADDRESS_MATCH_ELEMENT = Negatable(Arg("value",
    IpAddressType(),
    IpPrefixType(),
    AclReference(),
    KeyReference(),
    _recursive_list,
))

_ACL_LIST  = Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))
_ALLOW_ARG = lambda name: Keyword(Arg(name, ListOf(ADDRESS_MATCH_ELEMENT)))

_CLASS_ARG = Optional(Arg("zone_class",
    EnumType("IN", "CHAOS", "HESIOD", "ANY")))

_NOTIFY_VALUE = EnumType(
    "yes", "no", "explicit", "master-only", "primary-only")

_TRANSFER_FORMAT = EnumType("one-answer", "many-answers")

_CHECK_NAMES_ACTION = EnumType("fail", "warn", "ignore")


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------

ACL_STMT = StatementDef(
    "acl",
    Arg("name", StringType()),
    _ACL_LIST,
)


# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------

KEY_STMT = StatementDef(
    "key",
    Arg("name", StringType()),
    Context(
        Keyword(Arg("algorithm", TsigAlgorithm())),
        Keyword(Arg("secret",    Base64())),
    ),
)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

INET_STMT = StatementDef(
    "inet",
    Arg("address",    IpAddressType()),
    Optional(Keyword(Arg("port",      Integer(min=1, max=65535)))),
    Keyword(Arg("allow",              ListOf(ADDRESS_MATCH_ELEMENT))),
    Optional(Keyword(Arg("keys",      ListOf(KeyReference())))),
    Optional(Keyword(Arg("read-only", BooleanType()))),
)

UNIX_STMT = StatementDef(
    "unix",
    Arg("path",  StringType()),
    Optional(Keyword(Arg("perm",      Integer()))),
    Optional(Keyword(Arg("owner",     Integer()))),
    Optional(Keyword(Arg("group",     Integer()))),
    Optional(Keyword(Arg("keys",      ListOf(KeyReference())))),
    Optional(Keyword(Arg("read-only", BooleanType()))),
)

CONTROLS_STMT = StatementDef(
    "controls",
    Arg("controls", ListOf(OneOf(INET_STMT, UNIX_STMT))),
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

NULL_DEST_STMT = StatementDef(
    "null",  attr="destination",
)

STDERR_DEST_STMT = StatementDef(
    "stderr",  attr="destination",
)

FILE_DEST_STMT = StatementDef(
    "file",
    Arg("path", StringType()),
    Optional(Keyword(Arg("versions", OneOf(Integer(min=0), Unlimited())))),
    Optional(Keyword(Arg("size",     OneOf(Size(),         Unlimited())))),
    Optional(Keyword(Arg("suffix",   EnumType("increment", "timestamp")))),
    attr="destination",
)

SYSLOG_DEST_STMT = StatementDef(
    "syslog",
    Optional(Arg("facility", EnumType(
        "kern",   "user",   "mail",   "daemon", "auth",
        "syslog", "lpr",    "news",   "uucp",   "cron",
        "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7",
    ))),
    attr="destination",
)

CHANNEL_STMT = StatementDef(
    "channel",
    Arg("name", StringType()),
    Context(
        ExclusiveOf(
            NULL_DEST_STMT,
            STDERR_DEST_STMT,
            FILE_DEST_STMT,
            SYSLOG_DEST_STMT,
        ),
        Keyword(Arg("severity", OneOf(
            EnumType("critical", "error", "warning",
                     "notice",   "info",  "dynamic"),
            Keyword(Arg("debug", Integer(min=0))),
        ))),
        Keyword(Arg("print-time", OneOf(
            BooleanType(),
            EnumType("iso8601", "iso8601-utc", "local"),
        ))),
        Keyword(Arg("print-severity",  BooleanType())),
        Keyword(Arg("print-category",  BooleanType())),
        Keyword(Arg("buffered",        BooleanType())),
    ),
    attr="channels",
)

CATEGORY_STMT = StatementDef(
    "category",
    Arg("name", EnumType(
        "client",          "cname",         "config",
        "database",        "default",       "delegation-only",
        "dispatch",        "dnssec",        "dnstap",
        "edns-disabled",   "general",       "lame-servers",
        "network",         "notify",        "nsid",
        "queries",         "query-errors",  "rate-limit",
        "resolver",        "rpz",           "security",
        "serve-stale",     "spill",         "trust-anchor-telemetry",
        "unmatched",       "update",        "update-security",
        "xfer-in",         "xfer-out",      "zoneload",
    )),
    Arg("channels", ListOf(StringType())),
    attr="categories",
)

LOGGING_STMT = StatementDef(
    "logging",
    Context(
        Multiple(CHANNEL_STMT),
        Multiple(CATEGORY_STMT),
    ),
)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

SERVER_STMT = StatementDef(
    "server",
    Arg("address", IpAddressType()),
    Context(
        Keyword(Arg("bogus",           BooleanType())),
        Keyword(Arg("edns",            BooleanType())),
        Keyword(Arg("edns-udp-size",   Integer(min=512, max=4096))),
        Keyword(Arg("max-udp-size",    Integer(min=512, max=4096))),
        Keyword(Arg("tcp-only",        BooleanType())),
        Keyword(Arg("transfers",       Integer(min=0))),
        Keyword(Arg("transfer-format", _TRANSFER_FORMAT)),
        Keyword(Arg("keys",            ListOf(KeyReference()))),
        Keyword(Arg("request-expire",  BooleanType())),
        Keyword(Arg("request-ixfr",    BooleanType())),
    ),
)


# ---------------------------------------------------------------------------
# Zone
# ---------------------------------------------------------------------------

_ZONE_TYPE = EnumType(
    "primary", "secondary", "master", "slave",
    "hint", "stub", "forward", "redirect",
    "delegation-only", "in-view",
)

_UPDATE_POLICY_MATCHTYPE = EnumType(
    "6to4-self",    "external",        "krb5-self",
    "krb5-selfsub", "krb5-subdomain",  "krb5-subdomain-self-rhs",
    "ms-self",      "ms-selfsub",      "ms-subdomain",
    "ms-subdomain-self-rhs", "name",   "self",
    "selfsub",      "selfwild",        "subdomain",
    "tcp-self",     "wildcard",        "zonesub",
)

UPDATE_POLICY_RULE_STMT = StatementDef(
    "grant",
    Arg("action",    EnumType("grant", "deny")),
    Arg("identity",  StringType()),
    Arg("matchtype", _UPDATE_POLICY_MATCHTYPE),
    Optional(Arg("name",    StringType())),
    Arg("rrtypes",   Variadic(StringType())),
)

ZONE_STMT = StatementDef(
    "zone",
    Arg("name",       StringType()),
    _CLASS_ARG,
    Context(
        Keyword(Arg("type",           _ZONE_TYPE)),
        Keyword(Arg("file",           StringType())),
        Keyword(Arg("masters",        ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("primaries",      ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-query",    ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-transfer", ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-update",   ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-notify",   ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("also-notify",    ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("forwarders",     ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("forward",        EnumType("only", "first"))),
        Keyword(Arg("notify",         _NOTIFY_VALUE)),
        Keyword(Arg("key-directory",  StringType())),
        Keyword(Arg("auto-dnssec",    EnumType("allow", "maintain", "off"))),
        Keyword(Arg("dnssec-policy",  StringType())),
        Keyword(Arg("inline-signing", BooleanType())),
        Keyword(Arg("update-policy",  OneOf(
            EnumType("local"),
            ListOf(UPDATE_POLICY_RULE_STMT),
        ))),
        Keyword(Arg("check-names",    _CHECK_NAMES_ACTION)),
        Keyword(Arg("zone-statistics",BooleanType())),
        Keyword(Arg("serial-update-method", EnumType(
            "increment", "unixtime", "date"))),
    ),
)


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

_VIEW_CLASS_ARG = Optional(Arg("view_class",
    EnumType("IN", "CHAOS", "HESIOD", "ANY")))

VIEW_STMT = StatementDef(
    "view",
    Arg("name",       StringType()),
    _VIEW_CLASS_ARG,
    Context(
        Keyword(Arg("match-clients",       ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("match-destinations",  ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("match-recursive-only",BooleanType())),
        Multiple(ZONE_STMT, attr="zones"),
        Multiple(ACL_STMT,  attr="acls"),
        Multiple(KEY_STMT,  attr="keys"),
    ),
)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

OPTIONS_STMT = StatementDef(
    "options",
    Context(
        Keyword(Arg("directory",             StringType())),
        Keyword(Arg("named-xfer",            StringType())),
        Keyword(Arg("pid-file",              StringType())),
        Keyword(Arg("dump-file",             StringType())),
        Keyword(Arg("statistics-file",       StringType())),
        Keyword(Arg("memstatistics-file",    StringType())),
        Keyword(Arg("session-keyfile",       StringType())),
        Keyword(Arg("bindkeys-file",         StringType())),
        Keyword(Arg("managed-keys-directory",StringType())),
        Keyword(Arg("listen-on",   ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("listen-on-v6",ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("forwarders",  ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("forward",     EnumType("only", "first"))),
        Keyword(Arg("recursion",   BooleanType())),
        Keyword(Arg("allow-query",       ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-query-cache", ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-recursion",   ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("allow-transfer",    ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("blackhole",         ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("notify",            _NOTIFY_VALUE)),
        Keyword(Arg("also-notify",       ListOf(ADDRESS_MATCH_ELEMENT))),
        Keyword(Arg("dnssec-validation", EnumType("yes", "no", "auto"))),
        Deprecated(StatementDef("dnssec-enable",
            Keyword(Arg("dnssec-enable", BooleanType())))),
        Keyword(Arg("version",           StringType())),
        Keyword(Arg("hostname",          StringType())),
        Keyword(Arg("server-id",         StringType())),
        Keyword(Arg("port",              Integer(min=1, max=65535))),
        Keyword(Arg("max-cache-size",    OneOf(Size(), Unlimited()))),
        Keyword(Arg("max-cache-ttl",     Duration())),
        Keyword(Arg("max-ncache-ttl",    Duration())),
        Keyword(Arg("transfers-in",      Integer(min=0))),
        Keyword(Arg("transfers-out",     Integer(min=0))),
        Keyword(Arg("transfer-format",   _TRANSFER_FORMAT)),
        Keyword(Arg("auth-nxdomain",     BooleanType())),
        Keyword(Arg("empty-zones-enable",BooleanType())),
        Keyword(Arg("minimal-responses", OneOf(
            BooleanType(),
            EnumType("no-auth", "no-auth-recursive"),
        ))),
        Keyword(Arg("minimal-any",           BooleanType())),
        Keyword(Arg("tcp-clients",           Integer(min=0))),
        Keyword(Arg("recursive-clients",     Integer(min=0))),
        Keyword(Arg("resolver-query-timeout",Integer(min=0))),
        Keyword(Arg("interface-interval",    Integer(min=0))),
        Keyword(Arg("check-names",           _CHECK_NAMES_ACTION)),
    ),
)


# ---------------------------------------------------------------------------
# TLS (BIND 9.18+)
# ---------------------------------------------------------------------------

TLS_STMT = StatementDef(
    "tls",
    Arg("name", StringType()),
    Context(
        Keyword(Arg("key-file",                StringType())),
        Keyword(Arg("cert-file",               StringType())),
        Keyword(Arg("ca-file",                 StringType())),
        Keyword(Arg("dhparam-file",            StringType())),
        Keyword(Arg("remote-hostname",         StringType())),
        Keyword(Arg("protocols",               ListOf(StringType()))),
        Keyword(Arg("ciphers",                 StringType())),
        Keyword(Arg("prefer-server-ciphers",   BooleanType())),
        Keyword(Arg("session-tickets",         BooleanType())),
    ),
)


# ---------------------------------------------------------------------------
# HTTP (BIND 9.18+)
# ---------------------------------------------------------------------------

HTTP_STMT = StatementDef(
    "http",
    Arg("name", StringType()),
    Context(
        Keyword(Arg("endpoints",              ListOf(StringType()))),
        Keyword(Arg("listener-clients",       Integer(min=0))),
        Keyword(Arg("streams-per-connection", Integer(min=0))),
    ),
)


# ---------------------------------------------------------------------------
# Statistics channels
# ---------------------------------------------------------------------------

STATISTICS_CHANNELS_STMT = StatementDef(
    "statistics-channels",
    Arg("statistics_channels", ListOf(
        StatementDef(
            "inet",
            Arg("address", IpAddressType()),
            Optional(Keyword(Arg("port",  Integer(min=1, max=65535)))),
            Optional(Keyword(Arg("allow", ListOf(ADDRESS_MATCH_ELEMENT)))),
        ),
    )),
)


# ---------------------------------------------------------------------------
# Trust anchors / trusted-keys / managed-keys
# ---------------------------------------------------------------------------

_TRUST_ENTRY = StatementDef(
    "",    # no keyword — entries are purely positional
    Arg("domain",      StringType()),
    Arg("_sep",        EnumType(".")),
    Arg("anchor_type", EnumType(
        "initial-key", "static-key",
        "initial-ds",  "static-ds",
    )),
    Arg("flags",     Integer(min=0, max=65535)),
    Arg("protocol",  Integer(min=0, max=255)),
    Arg("algorithm", Integer(min=0, max=255)),
    Arg("key_data",  Base64()),
)

_TRUST_BLOCK = ListOf(_TRUST_ENTRY)

TRUSTED_KEYS_STMT = Deprecated(StatementDef(
    "trusted-keys",
    Arg("trusted_keys", _TRUST_BLOCK),
))

MANAGED_KEYS_STMT = Deprecated(StatementDef(
    "managed-keys",
    Arg("managed_keys", _TRUST_BLOCK),
))

TRUST_ANCHORS_STMT = StatementDef(
    "trust-anchors",
    Arg("trust_anchors", _TRUST_BLOCK),
)


# ---------------------------------------------------------------------------
# DNSSEC policy
# ---------------------------------------------------------------------------

_DNSSEC_KEY_ROLE_STMT = lambda role: StatementDef(
    role,
    Optional(Keyword(Arg("lifetime",  OneOf(Duration(), Unlimited())))),
    Optional(Keyword(Arg("algorithm", StringType()))),
)

DNSSEC_POLICY_STMT = StatementDef(
    "dnssec-policy",
    Arg("name", StringType()),
    Context(
        Keyword(Arg("dnskey-ttl",               Duration())),
        Keyword(Arg("keys",                     ListOf(
            OneOf(
                _DNSSEC_KEY_ROLE_STMT("csk"),
                _DNSSEC_KEY_ROLE_STMT("ksk"),
                _DNSSEC_KEY_ROLE_STMT("zsk"),
            ),
        ))),
        Keyword(Arg("max-zone-ttl",             Duration())),
        Keyword(Arg("parent-ds-ttl",            Duration())),
        Keyword(Arg("publish-safety",           Duration())),
        Keyword(Arg("retire-safety",            Duration())),
        Keyword(Arg("signatures-refresh",       Duration())),
        Keyword(Arg("signatures-validity",      Duration())),
        Keyword(Arg("signatures-validity-dnskey", Duration())),
        Keyword(Arg("zone-propagation-delay",   Duration())),
    ),
)


# ---------------------------------------------------------------------------
# Include
# ---------------------------------------------------------------------------

INCLUDE_STMT = StatementDef(
    "include",
    Arg("path", StringType()),
)


# ---------------------------------------------------------------------------
# Root schema
# ---------------------------------------------------------------------------

NAMED_CONF = Context(
    OPTIONS_STMT,
    Multiple(ACL_STMT),
    Multiple(KEY_STMT),
    Multiple(ZONE_STMT),
    Multiple(VIEW_STMT),
    CONTROLS_STMT,
    LOGGING_STMT,
    Multiple(SERVER_STMT),
    Multiple(TLS_STMT),
    Multiple(HTTP_STMT),
    STATISTICS_CHANNELS_STMT,
    TRUSTED_KEYS_STMT,
    MANAGED_KEYS_STMT,
    Multiple(TRUST_ANCHORS_STMT),
    Multiple(DNSSEC_POLICY_STMT),
    Multiple(INCLUDE_STMT),
)
