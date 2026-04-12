"""
isc.named.named_schema
~~~~~~~~~~~~~~~~~~~~~~
Complete DSL schema for ISC BIND named.conf.

Design
------
A Context contains only StatementDef entries (and Multiple/ExclusiveOf
wrappers around them). Each entry is matched by its keyword appearing as
the first token of a statement. Presence is always implicit — if the
keyword appears the statement is validated, if not the field defaults.

Keyword is used only within a StatementDef's param sequence, where it
describes a sentinel word on the same line as the statement keyword —
for example "port 953" or "read-only yes" in an inet statement.
"""

from __future__ import annotations

from isc.named.dsl import (
    Arg, Keyword, Optional, Negatable, Deprecated,
    Multiple, OneOf, ExclusiveOf, Variadic, ListOf, Context,
    StatementDef,
    IpAddressType, IpPrefixType, BooleanType, Integer,
    Size, StringType, EnumType, Duration, TsigAlgorithm, Base64, Unlimited,
    AclReference, KeyReference,
)

__all__ = ["NAMED_CONF"]


# ---------------------------------------------------------------------------
# Shared constructs
# ---------------------------------------------------------------------------

# Recursive address-match element — patched after definition
ADDRESS_MATCH_ELEMENT = Negatable(Arg("value",
    IpAddressType(),
    IpPrefixType(),
    AclReference(),
    KeyReference(),
    ListOf(None),
))
ADDRESS_MATCH_ELEMENT = Negatable(Arg("value",
    IpAddressType(),
    IpPrefixType(),
    AclReference(),
    KeyReference(),
    ListOf(ADDRESS_MATCH_ELEMENT),
))

_ACL_LIST          = Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))
_ALLOW             = lambda name: StatementDef(name, Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT)))
_CLASS_ARG         = Optional(Arg("zone_class", EnumType("IN", "CHAOS", "HESIOD", "ANY")))
_NOTIFY_VALUE      = EnumType("yes", "no", "explicit", "master-only", "primary-only")
_TRANSFER_FORMAT   = EnumType("one-answer", "many-answers")
_CHECK_NAMES       = EnumType("fail", "warn", "ignore")
_ZONE_TYPE         = EnumType(
    "primary", "secondary", "master", "slave",
    "hint", "stub", "forward", "redirect", "delegation-only", "in-view",
)


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------

ACL_STMT = StatementDef("acl",
    Arg("name", StringType()),
    _ACL_LIST,
)


# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------

KEY_STMT = StatementDef("key",
    Arg("name", StringType()),
    Context(
        StatementDef("algorithm", Arg("algorithm", TsigAlgorithm())),
        StatementDef("secret",    Arg("secret",    Base64())),
    ),
)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

INET_STMT = StatementDef("inet",
    Arg("address",    IpAddressType()),
    Optional(Keyword(Arg("port",      Integer(min=1, max=65535)))),
    Keyword(Arg("allow",              ListOf(ADDRESS_MATCH_ELEMENT))),
    Optional(Keyword(Arg("keys",      ListOf(KeyReference())))),
    Optional(Keyword(Arg("read-only", BooleanType()))),
)

UNIX_STMT = StatementDef("unix",
    Arg("path", StringType()),
    Optional(Keyword(Arg("perm",      Integer()))),
    Optional(Keyword(Arg("owner",     Integer()))),
    Optional(Keyword(Arg("group",     Integer()))),
    Optional(Keyword(Arg("keys",      ListOf(KeyReference())))),
    Optional(Keyword(Arg("read-only", BooleanType()))),
)

CONTROLS_STMT = StatementDef("controls",
    Arg("controls", ListOf(OneOf(INET_STMT, UNIX_STMT))),
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

NULL_DEST_STMT   = StatementDef("null",   attr="destination")
STDERR_DEST_STMT = StatementDef("stderr", attr="destination")

FILE_DEST_STMT = StatementDef("file",
    Arg("path", StringType()),
    Optional(Keyword(Arg("versions", OneOf(Integer(min=0), Unlimited())))),
    Optional(Keyword(Arg("size",     OneOf(Size(),         Unlimited())))),
    Optional(Keyword(Arg("suffix",   EnumType("increment", "timestamp")))),
    attr="destination",
)

SYSLOG_DEST_STMT = StatementDef("syslog",
    Optional(Arg("facility", EnumType(
        "kern",   "user",   "mail",   "daemon", "auth",
        "syslog", "lpr",    "news",   "uucp",   "cron",
        "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7",
    ))),
    attr="destination",
)

CHANNEL_STMT = StatementDef("channel",
    Arg("name", StringType()),
    Context(
        ExclusiveOf(
            NULL_DEST_STMT,
            STDERR_DEST_STMT,
            FILE_DEST_STMT,
            SYSLOG_DEST_STMT,
        ),
        StatementDef("severity", Arg("severity", OneOf(
            EnumType("critical", "error", "warning", "notice", "info", "dynamic"),
            Keyword(Arg("debug", Integer(min=0))),
        ))),
        StatementDef("print-time",     Arg("print-time", OneOf(
            BooleanType(),
            EnumType("iso8601", "iso8601-utc", "local"),
        ))),
        StatementDef("print-severity", Arg("print-severity", BooleanType())),
        StatementDef("print-category", Arg("print-category", BooleanType())),
        StatementDef("buffered",       Arg("buffered",       BooleanType())),
    ),
    attr="channels",
)

CATEGORY_STMT = StatementDef("category",
    Arg("name", EnumType(
        "client",        "cname",       "config",
        "database",      "default",     "delegation-only",
        "dispatch",      "dnssec",      "dnstap",
        "edns-disabled", "general",     "lame-servers",
        "network",       "notify",      "nsid",
        "queries",       "query-errors","rate-limit",
        "resolver",      "rpz",         "security",
        "serve-stale",   "spill",       "trust-anchor-telemetry",
        "unmatched",     "update",      "update-security",
        "xfer-in",       "xfer-out",    "zoneload",
    )),
    Arg("channels", ListOf(StringType())),
    attr="categories",
)

LOGGING_STMT = StatementDef("logging",
    Context(
        Multiple(CHANNEL_STMT),
        Multiple(CATEGORY_STMT),
    ),
)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

SERVER_STMT = StatementDef("server",
    Arg("address", IpAddressType()),
    Context(
        StatementDef("bogus",           Arg("bogus",           BooleanType())),
        StatementDef("edns",            Arg("edns",            BooleanType())),
        StatementDef("edns-udp-size",   Arg("edns-udp-size",   Integer(min=512, max=4096))),
        StatementDef("max-udp-size",    Arg("max-udp-size",    Integer(min=512, max=4096))),
        StatementDef("tcp-only",        Arg("tcp-only",        BooleanType())),
        StatementDef("transfers",       Arg("transfers",       Integer(min=0))),
        StatementDef("transfer-format", Arg("transfer-format", _TRANSFER_FORMAT)),
        StatementDef("keys",            Arg("keys",            ListOf(KeyReference()))),
        StatementDef("request-expire",  Arg("request-expire",  BooleanType())),
        StatementDef("request-ixfr",    Arg("request-ixfr",    BooleanType())),
    ),
)


# ---------------------------------------------------------------------------
# Zone
# ---------------------------------------------------------------------------

_UPDATE_POLICY_MATCHTYPE = EnumType(
    "6to4-self",    "external",       "krb5-self",
    "krb5-selfsub", "krb5-subdomain", "krb5-subdomain-self-rhs",
    "ms-self",      "ms-selfsub",     "ms-subdomain",
    "ms-subdomain-self-rhs", "name",  "self",
    "selfsub",      "selfwild",       "subdomain",
    "tcp-self",     "wildcard",       "zonesub",
)

UPDATE_POLICY_RULE_STMT = StatementDef("grant",
    Arg("action",    EnumType("grant", "deny")),
    Arg("identity",  StringType()),
    Arg("matchtype", _UPDATE_POLICY_MATCHTYPE),
    Optional(Arg("name",    StringType())),
    Arg("rrtypes",   Variadic(StringType())),
)

ZONE_STMT = StatementDef("zone",
    Arg("name",       StringType()),
    _CLASS_ARG,
    Context(
        StatementDef("type",           Arg("type",           _ZONE_TYPE)),
        StatementDef("file",           Arg("file",           StringType())),
        StatementDef("masters",        Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("primaries",      Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-query",    Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-transfer", Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-update",   Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-notify",   Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("also-notify",    Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("forwarders",     Arg("elements",       ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("forward",        Arg("forward",        EnumType("only", "first"))),
        StatementDef("notify",         Arg("notify",         _NOTIFY_VALUE)),
        StatementDef("key-directory",  Arg("key-directory",  StringType())),
        StatementDef("auto-dnssec",    Arg("auto-dnssec",    EnumType("allow", "maintain", "off"))),
        StatementDef("dnssec-policy",  Arg("dnssec-policy",  StringType())),
        StatementDef("inline-signing", Arg("inline-signing", BooleanType())),
        StatementDef("update-policy",  Arg("update-policy",  OneOf(
            EnumType("local"),
            ListOf(UPDATE_POLICY_RULE_STMT),
        ))),
        StatementDef("check-names",    Arg("check-names",    _CHECK_NAMES)),
        StatementDef("zone-statistics",Arg("zone-statistics",BooleanType())),
        StatementDef("serial-update-method", Arg("serial-update-method",
            EnumType("increment", "unixtime", "date"))),
    ),
)


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

VIEW_STMT = StatementDef("view",
    Arg("name",       StringType()),
    Optional(Arg("view_class", EnumType("IN", "CHAOS", "HESIOD", "ANY"))),
    Context(
        StatementDef("match-clients",        Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("match-destinations",   Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("match-recursive-only", Arg("match-recursive-only", BooleanType())),
        Multiple(ZONE_STMT, attr="zones"),
        Multiple(ACL_STMT,  attr="acls"),
        Multiple(KEY_STMT,  attr="keys"),
    ),
)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

OPTIONS_STMT = StatementDef("options",
    Context(
        StatementDef("directory",              Arg("directory",              StringType())),
        StatementDef("named-xfer",             Arg("named-xfer",             StringType())),
        StatementDef("pid-file",               Arg("pid-file",               StringType())),
        StatementDef("dump-file",              Arg("dump-file",              StringType())),
        StatementDef("statistics-file",        Arg("statistics-file",        StringType())),
        StatementDef("memstatistics-file",     Arg("memstatistics-file",     StringType())),
        StatementDef("session-keyfile",        Arg("session-keyfile",        StringType())),
        StatementDef("bindkeys-file",          Arg("bindkeys-file",          StringType())),
        StatementDef("managed-keys-directory", Arg("managed-keys-directory", StringType())),
        StatementDef("listen-on",    Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("listen-on-v6", Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("forwarders",   Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("forward",            Arg("forward",            EnumType("only", "first"))),
        StatementDef("recursion",          Arg("recursion",          BooleanType())),
        StatementDef("allow-query",        Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-query-cache",  Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-recursion",    Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("allow-transfer",     Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("blackhole",          Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("notify",             Arg("notify",             _NOTIFY_VALUE)),
        StatementDef("also-notify",        Arg("elements",           ListOf(ADDRESS_MATCH_ELEMENT))),
        StatementDef("dnssec-validation",  Arg("dnssec-validation",  EnumType("yes", "no", "auto"))),
        Deprecated(StatementDef("dnssec-enable", Arg("dnssec-enable", BooleanType()))),
        StatementDef("version",            Arg("version",            StringType())),
        StatementDef("hostname",           Arg("hostname",           StringType())),
        StatementDef("server-id",          Arg("server-id",          StringType())),
        StatementDef("port",               Arg("port",               Integer(min=1, max=65535))),
        StatementDef("max-cache-size",     Arg("max-cache-size",     OneOf(Size(), Unlimited()))),
        StatementDef("max-cache-ttl",      Arg("max-cache-ttl",      Duration())),
        StatementDef("max-ncache-ttl",     Arg("max-ncache-ttl",     Duration())),
        StatementDef("transfers-in",       Arg("transfers-in",       Integer(min=0))),
        StatementDef("transfers-out",      Arg("transfers-out",      Integer(min=0))),
        StatementDef("transfer-format",    Arg("transfer-format",    _TRANSFER_FORMAT)),
        StatementDef("auth-nxdomain",      Arg("auth-nxdomain",      BooleanType())),
        StatementDef("empty-zones-enable", Arg("empty-zones-enable", BooleanType())),
        StatementDef("minimal-responses",  Arg("minimal-responses",  OneOf(
            BooleanType(), EnumType("no-auth", "no-auth-recursive"),
        ))),
        StatementDef("minimal-any",            Arg("minimal-any",            BooleanType())),
        StatementDef("tcp-clients",            Arg("tcp-clients",            Integer(min=0))),
        StatementDef("recursive-clients",      Arg("recursive-clients",      Integer(min=0))),
        StatementDef("resolver-query-timeout", Arg("resolver-query-timeout", Integer(min=0))),
        StatementDef("interface-interval",     Arg("interface-interval",     Integer(min=0))),
        StatementDef("check-names",            Arg("check-names",            _CHECK_NAMES)),
    ),
)


# ---------------------------------------------------------------------------
# TLS (BIND 9.18+)
# ---------------------------------------------------------------------------

TLS_STMT = StatementDef("tls",
    Arg("name", StringType()),
    Context(
        StatementDef("key-file",              Arg("key-file",              StringType())),
        StatementDef("cert-file",             Arg("cert-file",             StringType())),
        StatementDef("ca-file",               Arg("ca-file",               StringType())),
        StatementDef("dhparam-file",          Arg("dhparam-file",          StringType())),
        StatementDef("remote-hostname",       Arg("remote-hostname",       StringType())),
        StatementDef("protocols",             Arg("protocols",             ListOf(StringType()))),
        StatementDef("ciphers",               Arg("ciphers",               StringType())),
        StatementDef("prefer-server-ciphers", Arg("prefer-server-ciphers", BooleanType())),
        StatementDef("session-tickets",       Arg("session-tickets",       BooleanType())),
    ),
)


# ---------------------------------------------------------------------------
# HTTP (BIND 9.18+)
# ---------------------------------------------------------------------------

HTTP_STMT = StatementDef("http",
    Arg("name", StringType()),
    Context(
        StatementDef("endpoints",              Arg("endpoints",              ListOf(StringType()))),
        StatementDef("listener-clients",       Arg("listener-clients",       Integer(min=0))),
        StatementDef("streams-per-connection", Arg("streams-per-connection", Integer(min=0))),
    ),
)


# ---------------------------------------------------------------------------
# Statistics channels
# ---------------------------------------------------------------------------

STATISTICS_CHANNELS_STMT = StatementDef("statistics-channels",
    Arg("statistics_channels", ListOf(
        StatementDef("inet",
            Arg("address", IpAddressType()),
            Optional(Keyword(Arg("port",  Integer(min=1, max=65535)))),
            Optional(Keyword(Arg("allow", ListOf(ADDRESS_MATCH_ELEMENT)))),
        ),
    )),
)


# ---------------------------------------------------------------------------
# Trust anchors / trusted-keys / managed-keys
# ---------------------------------------------------------------------------

_TRUST_ENTRY = StatementDef("",   # positional — no keyword
    Arg("domain",      StringType()),
    Arg("_sep",        EnumType(".")),
    Arg("anchor_type", EnumType("initial-key", "static-key", "initial-ds", "static-ds")),
    Arg("flags",       Integer(min=0, max=65535)),
    Arg("protocol",    Integer(min=0, max=255)),
    Arg("algorithm",   Integer(min=0, max=255)),
    Arg("key_data",    Base64()),
)

_TRUST_BLOCK = ListOf(_TRUST_ENTRY)

TRUSTED_KEYS_STMT  = Deprecated(StatementDef("trusted-keys", Arg("trusted_keys",  _TRUST_BLOCK)))
MANAGED_KEYS_STMT  = Deprecated(StatementDef("managed-keys", Arg("managed_keys",  _TRUST_BLOCK)))
TRUST_ANCHORS_STMT = StatementDef("trust-anchors",            Arg("trust_anchors", _TRUST_BLOCK))


# ---------------------------------------------------------------------------
# DNSSEC policy
# ---------------------------------------------------------------------------

def _key_role(role: str) -> StatementDef:
    return StatementDef(role,
        Optional(Keyword(Arg("lifetime",  OneOf(Duration(), Unlimited())))),
        Optional(Keyword(Arg("algorithm", StringType()))),
    )

DNSSEC_POLICY_STMT = StatementDef("dnssec-policy",
    Arg("name", StringType()),
    Context(
        StatementDef("dnskey-ttl",   Arg("dnskey-ttl",   Duration())),
        StatementDef("keys",         Arg("keys",         ListOf(OneOf(
            _key_role("csk"), _key_role("ksk"), _key_role("zsk"),
        )))),
        StatementDef("max-zone-ttl",             Arg("max-zone-ttl",             Duration())),
        StatementDef("parent-ds-ttl",            Arg("parent-ds-ttl",            Duration())),
        StatementDef("publish-safety",           Arg("publish-safety",           Duration())),
        StatementDef("retire-safety",            Arg("retire-safety",            Duration())),
        StatementDef("signatures-refresh",       Arg("signatures-refresh",       Duration())),
        StatementDef("signatures-validity",      Arg("signatures-validity",      Duration())),
        StatementDef("signatures-validity-dnskey", Arg("signatures-validity-dnskey", Duration())),
        StatementDef("zone-propagation-delay",   Arg("zone-propagation-delay",   Duration())),
    ),
)


# ---------------------------------------------------------------------------
# Include
# ---------------------------------------------------------------------------

INCLUDE_STMT = StatementDef("include",
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
