# zeek-tds

A [Zeek](https://zeek.org) protocol analyzer for Microsoft SQL Server's wire
protocol, Tabular Data Stream (TDS), written in [Spicy](https://docs.zeek.org/projects/spicy).
It turns SQL Server traffic into five logs:

| Log | One line per | What you get |
| --- | --- | --- |
| `tds_login.log` | connection | who connected from where with which driver: client host name, login, application, library, database, TDS version, encryption negotiated, the server's product and version, and whether the login succeeded or failed and why |
| `tds_sql_batch.log` | SQL batch | the statement text and its transaction descriptor; transaction manager requests (begin, commit, rollback) appear here too |
| `tds_rpc.log` | remote procedure call | procedure name, every parameter as `@name type = value`, and for prepared statements the SQL text and the handle they run under |
| `tds_error.log` | server ERROR token | number, severity, state, message, procedure and line; INFO messages optionally |
| `tds.log` | TDS message | direction, type, size, packets, and for results the rows returned, rows affected and errors |

Sessions that negotiate encryption during PRELOGIN are handed to Zeek's SSL
analyzer, so `ssl.log` and `x509.log` cover the SQL session and
`tds_login.log` records that it went encrypted.

## Why

TDS is how every client talks to SQL Server, and SQL Server is how a great many
historians, MES systems, and line-of-business applications keep their data. In
a threat hunt the questions are always the same: which hosts speak to the
database, as whom, with what tool, and what do they run. Wireshark answers them
one capture at a time; Zeek answers them continuously, for every session, with
the connection identifiers that join to `conn.log` and the rest of the
monitoring stack.

The existing Zeek package for TDS is a BinPAC plugin that no longer builds on
current Zeek and misparses procedure calls addressed by number, which is
exactly how drivers ship ad-hoc SQL (`sp_executesql`, `sp_prepexec`). This
analyzer handles those, reassembles multi-packet messages, decodes parameter
values by type, and reads the server's response tokens, on Zeek 7 and 8.

## Example

A pytds client inserting readings into a table, from `tds_rpc.log`:

```
procedure      sp_executesql
proc_id        10
parameters     @p1 nvarchar(max) = INSERT INTO dbo.readings (tag, value, quality, ts ...) VALUES (@P1, @P2 ...),
               @p2 nvarchar(max) = @P1 NVARCHAR(MAX),@P2 FLOAT,@P3 INT,@P4 DATETIME2(6) ...,
               @P1 nvarchar(max) = PUMP-001.FLOW, @P2 floatn(8) = 13.5, @P3 intn(4) = 192,
               @P4 datetime2 = 2026-09-05 12:00:01.000000, ...
statement      INSERT INTO dbo.readings (tag, value, quality, ts ...) VALUES (@P1, @P2 ...)
```

A failed login, from `tds_login.log`:

```
hostname       workstation-01
username       sa
has_password   T
app_name       zeek-tds-badpw
library        Python TDS Library
tds_version    7.4
success        F
error_number   18456
error_message  Login failed for user 'sa'.
```

## Installation

Requires Zeek 7.0 or newer with Spicy (included in the official builds and
containers) and a C++ toolchain for `zkg` to compile the analyzer.

```bash
zkg install zeek-tds
```

or from a checkout:

```bash
zkg install .
```

The analyzer registers itself for TCP port 1433 and is also enabled by
signature when a PRELOGIN or LOGIN7 message is seen on any port.

## Options

```zeek
# Additional ports.
redef TDS::ports += { 14330/tcp };

# Also log INFO messages (severity below 11) to tds_error.log.
redef TDS::log_info_messages = T;

# Statements and values are truncated at 1024 bytes; raise or set to 0 for no limit.
# Zeek caps each log field at Log::default_max_field_string_bytes (4096).
redef TDS::max_text = 8192;
redef Log::default_max_field_string_bytes = 65536;
```

## What is and is not decoded

Decoded: packet framing and message reassembly in both directions; PRELOGIN
options and the encryption negotiation; LOGIN7 (all fields except the
obfuscated password, which is only reported as present); SQL batches with
ALL_HEADERS; RPC requests including numbered procedures, multiple batches, and
parameters of every fixed-length, byte-length, ushort-length, long-length and
partially-length-prefixed type, rendered by type (integers, decimals, money,
floats, strings, binary, GUIDs, all date and time types); transaction manager
requests; the server token stream: LOGINACK, ENVCHANGE, ERROR, INFO, DONE,
RETURNSTATUS, RETURNVALUE, COLMETADATA, ROW and NBCROW (values are parsed to
keep the stream aligned, row counts are logged), FEATUREEXTACK.

Not decoded: the contents of bulk-load rows and SSPI blobs (logged as messages
only); result row values; TDS 8.0 (TLS from the first byte, which the SSL
analyzer sees on its own); pre-TDS7 Sybase-style logins. When the client and
server agree on encryption, only PRELOGIN is visible; with the common
"encrypt login only" setting, everything except LOGIN7 is.

TDS 7.1 and 7.2+ differ in a few token layouts. The analyzer learns the
version from LOGIN7 or LOGINACK and, when it joins a connection mid-stream,
infers it from whether requests carry ALL_HEADERS.

## Development

The test suite runs Zeek over the captures in `testing/Traces` and compares
every log against a baseline. The captures come from Azure SQL Edge (the SQL
Server 2019 engine, TDS 7.4) driven by pytds and FreeTDS, plus a 2009 capture
of TDS 7.1 and 7.2 clients; client identifiers in them are synthetic.

```bash
zkg test .            # or: cd testing && btest -c btest.cfg
```

To work without installing, compile the analyzer into an object file and pass
it to Zeek directly:

```bash
spicyz -o tds.hlto analyzer/tds.spicy analyzer/zeek_tds.spicy analyzer/tds.evt
zeek -Cr testing/Traces/sqledge-pytds-workload.pcap tds.hlto scripts
```

Both work inside the official `zeek/zeek` container once `g++`, `cmake` and
`make` are installed; CI does exactly that.

## License

Apache 2.0, see [LICENSE](LICENSE).
