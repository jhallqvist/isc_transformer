ADDRESS_MATCH_ELEMENT = Negatable(Arg("value",
    IpAddressType(),
    IpPrefixType(),
    AclReference(),
    KeyReference(),
    ListOf(ADDRESS_MATCH_ELEMENT, node_class=AddressMatchElement),
))

ACL_STMT = StatementDef(
    keyword="acl",
    node_class=AclStatement,
    params=[
        Arg("name",     StringType()),
        Arg("elements", ListOf(ADDRESS_MATCH_ELEMENT, node_class=AddressMatchElement)),
    ]
)

# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

INET_STMT = StatementDef(
    keyword="inet",
    node_class=InetChannel,
    params=[
        Arg("address",   IpAddressType()),
        Optional(Keyword(Arg("port",      PortType()))),
        Keyword(Arg("allow",              ListOf(ADDRESS_MATCH_ELEMENT, node_class=AddressMatchElement))),
        Optional(Keyword(Arg("keys",      ListOf(Arg("key", KeyReference()), node_class=str)))),
        Optional(Keyword(Arg("read-only", BooleanType()))),
    ]
)

UNIX_STMT = StatementDef(
    keyword="unix",
    node_class=UnixChannel,
    params=[
        Arg("path",  StringType()),
        Optional(Keyword(Arg("perm",      Integer()))),
        Optional(Keyword(Arg("owner",     Integer()))),
        Optional(Keyword(Arg("group",     Integer()))),
        Optional(Keyword(Arg("keys",      ListOf(Arg("key", KeyReference()), node_class=str)))),
        Optional(Keyword(Arg("read-only", BooleanType()))),
    ]
)

CONTROLS_STMT = StatementDef(
    keyword="controls",
    node_class=None,
    params=[
        Arg("controls", ListOf(
            ExclusiveOf(INET_STMT, UNIX_STMT),
            node_class=None,
        )),
    ]
)

# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------

KEY_STMT = StatementDef(
    keyword="key",
    node_class=KeyStatement,
    params=[
        Arg("name", StringType()),
        Context(
            Keyword(Arg("algorithm", TsigAlgorithm())),
            Keyword(Arg("secret",    Base64())),
        )
    ]
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

NULL_DEST_STMT = StatementDef(
    keyword="null",
    node_class=NullDestination,
    params=[]
)

STDERR_DEST_STMT = StatementDef(
    keyword="stderr",
    node_class=StderrDestination,
    params=[]
)

FILE_DEST_STMT = StatementDef(
    keyword="file",
    node_class=FileDestination,
    params=[
        Arg("path", StringType()),
        Optional(Keyword(Arg("versions", OneOf(Integer(), Unlimited())))),
        Optional(Keyword(Arg("size",     OneOf(Size(),    Unlimited())))),
        Optional(Keyword(Arg("suffix",   EnumType("increment", "timestamp")))),
    ]
)

SYSLOG_DEST_STMT = StatementDef(
    keyword="syslog",
    node_class=SyslogDestination,
    params=[
        Optional(Arg("facility", EnumType(
            "kern", "user", "mail", "daemon", "auth", "syslog",
            "lpr",  "news", "uucp", "cron",   "local0", "local1",
            "local2", "local3", "local4", "local5", "local6", "local7",
        ))),
    ]
)

CHANNEL_STMT = StatementDef(
    keyword="channel",
    node_class=ChannelStatement,
    params=[
        Arg("name", StringType()),
        Context(
            ExclusiveOf(
                NULL_DEST_STMT,
                STDERR_DEST_STMT,
                FILE_DEST_STMT,
                SYSLOG_DEST_STMT,
            ),
            Keyword(Arg("severity", OneOf(
                EnumType("critical", "error", "warning", "notice",
                         "info", "dynamic"),
                Keyword(Arg("debug", Integer(min=0))),
            ))),
            Keyword(Arg("print-time",      OneOf(
                BooleanType(),
                EnumType("iso8601", "iso8601-utc", "local"),
            ))),
            Keyword(Arg("print-severity",  BooleanType())),
            Keyword(Arg("print-category",  BooleanType())),
            Keyword(Arg("buffered",        BooleanType())),
        )
    ]
)

CATEGORY_STMT = StatementDef(
    keyword="category",
    node_class=CategoryStatement,
    params=[
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
        Arg("channels", ListOf(Arg("channel", StringType()), node_class=str)),
    ]
)

LOGGING_STMT = StatementDef(
    keyword="logging",
    node_class=LoggingStatement,
    params=[
        Context(
            Multiple(CHANNEL_STMT),
            Multiple(CATEGORY_STMT),
        )
    ]
)



NAMED_CONF = Context(
    Multiple(ACL_STMT),
    Multiple(CONTROLS_STMT),
    Multiple(KEY_STMT),
    Multiple(KEY_STORE_STMT),
    LOGGING_STMT,
    Multiple(REMOTE_SERVERS_STMT),
    OPTIONS_STMT,
    Multiple(SERVER_STMT),
    Multiple(STATISTICS_CHANNELS_STMT),
    Multiple(TLS_STMT),
    Multiple(HTTP_STMT),
    Multiple(TRUST_ANCHORS_STMT),
    Multiple(DNSSEC_POLICY_STMT),
    Multiple(MANAGED_KEYS_STMT),
    Multiple(TRUSTED_KEYS_STMT),
    Multiple(VIEW_STMT),
    Multiple(ZONE_STMT),
)
