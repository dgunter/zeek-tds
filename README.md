# zeek-tds

A [Zeek](https://zeek.org) protocol analyzer for Microsoft SQL Server's wire
protocol, Tabular Data Stream (TDS), written in [Spicy](https://docs.zeek.org/projects/spicy).
It turns SQL Server traffic into five logs, one per question a hunter asks of a
database: who connected, what they ran, what they called, what went wrong, and
how much came back.

| Log | One line per | Answers |
| --- | --- | --- |
| [`tds_login.log`](#tds_loginlog) | connection | who connected, from which host and tool, as whom, to which database, and whether the login succeeded |
| [`tds_sql_batch.log`](#tds_sql_batchlog) | SQL batch | the statement text as sent, with its transaction |
| [`tds_rpc.log`](#tds_rpclog) | procedure call | procedure name, every parameter with type and value, and the SQL text inside prepared statements |
| [`tds_error.log`](#tds_errorlog) | server error | number, severity, state and message |
| [`tds.log`](#tdslog) | TDS message | direction, type, size, and for results the rows returned and affected |

Sessions that negotiate encryption are handed to Zeek's SSL analyzer, so
`ssl.log` and `x509.log` cover them and `tds_login.log` records that the
session went encrypted.

Every example below is real output from the captures in `testing/Traces`,
shown with `zeek-cut`. The connection columns `ts`, `uid` and `id.*` open
every log and are omitted here.

## Why

TDS is how every client talks to SQL Server, and SQL Server is where a great
many historians, MES systems and line-of-business applications keep their
data. The hunting questions are always the same: which hosts speak to the
database, as whom, with what tool, and what do they run. Wireshark answers
them one capture at a time. Zeek answers them continuously, for every session,
with the `uid` that joins to `conn.log`, `ssl.log` and the rest of the stack.

The existing Zeek package for TDS is a BinPAC plugin that no longer builds on
current Zeek and misparses procedure calls addressed by number, which is
exactly how drivers ship ad-hoc SQL (`sp_executesql`, `sp_prepexec`,
`sp_execute`). This analyzer decodes those with their parameters, reassembles
multi-packet messages, renders parameter values by type, reads the server's
response tokens, and follows the connection into TLS. It runs on Zeek 7 and 8.

## tds_login.log

One line per connection, written when the server answers the login (or when
the connection ends, if it never did). It merges the client's PRELOGIN, its
LOGIN7, and the server's PRELOGIN reply, LOGINACK and first ENVCHANGE.

A Python client connecting with SQL authentication:

```
tds_version             7.4
client_version          1.0.0.0
server_version          15.0.2000.0
client_encryption       not_supported
server_encryption       not_supported
encrypted               F
instance                MSSQLServer
hostname                workstation-01
username                sa
has_password            T
integrated_auth         F
app_name                zeek-tds-corpus
library                 Python TDS Library
database                zeektds
client_pid              35535
client_mac              02:42:AC:11:00:02
odbc                    T
server_product          Microsoft SQL Server
server_product_version  15.0.2000
server_tds_version      7.4
initial_database        zeektds
success                 T
```

The same client with a wrong password. The server answers with error 18456
before any LOGINACK, and the line records it:

```
hostname        workstation-01
username        sa
app_name        zeek-tds-badpw
library         Python TDS Library
tds_version     7.4
success         F
error_number    18456
error_message   Login failed for user 'sa'.
```

Fields worth knowing:

| Field | Meaning |
| --- | --- |
| `hostname`, `client_pid`, `client_mac` | what the client says about itself: machine name, process id, and the NIC address LOGIN7 carries as ClientID |
| `username`, `has_password`, `integrated_auth` | SQL authentication with a password, or Windows integrated authentication (SSPI); the password itself is never decoded |
| `app_name`, `library`, `odbc`, `oledb` | the application and driver: "Python TDS Library", "Core .Net SqlClient Data Provider", "ODBC Driver 18 for SQL Server", jTDS, "OSQL-32" and so on |
| `database`, `initial_database` | the database asked for, and the one the server actually put the session in |
| `client_encryption`, `server_encryption`, `encrypted` | what each side asked for in PRELOGIN, and whether TLS actually started |
| `server_product`, `server_product_version`, `server_tds_version` | from LOGINACK: product name, version such as `15.0.2000` (SQL Server 2019) or `16.0.x` (2022), and the TDS version the server settled on |
| `success`, `error_number`, `error_message` | LOGINACK seen, or the ERROR token that came instead |
| `read_only_intent`, `change_password`, `attach_db`, `mars`, `language` | the rarer LOGIN7 options |

Hunting notes: an `app_name` or `library` you do not recognise talking to a
historian; `sa` or another shared account from a workstation; a `hostname`
that does not match the DNS name of `id.orig_h`; bursts of `success F` from one
source; `encrypted F` where policy says otherwise.

When the two sides negotiate encryption only for the login (FreeTDS's and
many drivers' default), LOGIN7 is inside TLS and the client fields are empty,
but the server's answer is in the clear, so the login outcome is still known:

```
tds_version        -
client_version     9.0.0.0
client_encryption  off
server_encryption  off
encrypted          T
server_product     Microsoft SQL Server
initial_database   zeektds
success            T
```

With encryption for the whole session, only the PRELOGIN exchange is visible.
The line then shows the negotiation and the session continues in `ssl.log`
under the same `uid`:

```
client_encryption  on
server_encryption  on
encrypted          T
server_version     15.0.2000.0
```

```
# ssl.log, same uid
version  TLSv12
cipher   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
server_name  127.0.0.1
```

## tds_sql_batch.log

One line per SQL batch: the statement text exactly as the client sent it,
with the transaction descriptor from the batch's headers. Transaction manager
requests, which have no SQL text, appear as `<transaction manager: begin>`,
`commit` or `rollback`, so the transaction boundaries are visible in one place.

```
transaction_descriptor  query
0                       IF OBJECT_ID('dbo.readings') IS NULL CREATE TABLE dbo.readings (\x0a  id int IDENTITY PRIMARY KEY, tag nvarchar(64) NOT NULL, ...
0                       TRUNCATE TABLE dbo.readings
0                       SELECT * FROM dbo.readings ORDER BY id
0                       CREATE PROCEDURE dbo.usp_get_readings @tag nvarchar(64), @min float = 0, @count int OUTPUT AS\x0a  BEGIN SELECT @count = COUNT(*) ...
0                       <transaction manager: begin>
219043332162            UPDATE dbo.readings SET quality = 0 WHERE id = 1
0                       <transaction manager: commit>
219043332163            UPDATE dbo.readings SET quality = 1 WHERE id = 2
0                       <transaction manager: rollback>
0                       SELECT * FROM dbo.does_not_exist
0                       RAISERROR('custom failure %d', 16, 1, 42)
0                       PRINT 'hello from tds'
```

A FreeTDS client does its transactions in SQL instead; the descriptor the
server handed out in ENVCHANGE then tags every statement inside them:

```
0                       BEGIN TRAN
219043332097            SELECT TOP 10 id, tag, value, ts FROM dbo.readings WHERE quality IS NOT NULL
219043332097            SELECT 42 AS n, N'freetds' AS s
219043332097            COMMIT TRAN
```

Newlines in statements are escaped as `\x0a`, and statements longer than
`TDS::max_text` (1024 bytes by default) are cut; see [Options](#options).

Hunting notes: `xp_cmdshell`, `sp_configure`, `OPENROWSET`, `BULK INSERT`,
`sp_addlogin`, `ALTER LOGIN`, `sp_OACreate`, `xp_dirtree`, `SELECT ... INTO
OUTFILE`-style exfiltration, `DROP` and `TRUNCATE` on historian tables,
`WAITFOR DELAY` and `IF ... ELSE` probes typical of injection, and any batch
from a host that normally only calls procedures.

## tds_rpc.log

One line per remote procedure call. The procedure is named, or resolved from
its number for the fifteen special procedures drivers use for prepared and
parameterised statements, and every parameter is rendered as `@name type =
value`. For `sp_executesql`, `sp_prepare`, `sp_prepexec` and the cursor
procedures, the SQL text they carry is lifted into `statement`, and prepared
statement handles into `handle`, so an `sp_execute` can be tied back to the
`sp_prepexec` that defined it.

A parameterised insert from a Python client, which the driver ships as
`sp_executesql` with typed parameters. Every TDS data type is rendered as a
value:

```
procedure   sp_executesql
proc_id     10
parameters  @p1 nvarchar(max) = INSERT INTO dbo.readings (tag, value, quality, ts, note, blob, amount, price, flag, guid, d, t, dto, big, xmlcol) VALUES (@P1, @P2, ... @P15),
            @p2 nvarchar(max) = @P1 NVARCHAR(MAX),@P2 FLOAT,@P3 INT,@P4 DATETIME2(6),@P5 NVARCHAR(MAX),@P6 VARBINARY(8000),@P7 DECIMAL(8, 4),@P8 DECIMAL(4, 2),@P9 BIT,@P10 UNIQUEIDENTIFIER,@P11 DATE,@P12 TIME(6),@P13 DATETIMEOFFSET(6),@P14 BIGINT,@P15 NVARCHAR(MAX),
            @P1 nvarchar(max) = PUMP-001.FLOW,
            @P2 floatn(8) = 13.5,
            @P3 intn(4) = 192,
            @P4 datetime2 = 2026-09-05 12:00:01.000000,
            @P5 nvarchar(max) = note 1,
            @P6 varbinary(8000) = 0x0102,
            @P7 decimaln(8,4) = 1235.5678,
            @P8 decimaln(4,2) = 99.99,
            @P9 bitn = true,
            @P10 uniqueidentifier = 670DBD95-D6FB-4F2F-BD7B-97486DC7F6DB,
            @P11 date = 2026-09-05,
            @P12 time = 13:14:15.123456,
            @P13 datetimeoffset = 2026-09-05 06:02:03.000000 -05:00,
            @P14 intn(8) = 1099511627777,
            @P15 nvarchar(max) = <r><a>1</a></r>
statement   INSERT INTO dbo.readings (tag, value, quality, ts, note, blob, amount, price, flag, guid, d, t, dto, big, xmlcol) VALUES (@P1, @P2, ... @P15)
```

A query with one parameter, and a user-defined procedure with an output
parameter (`output` marks parameters passed by reference):

```
procedure   sp_executesql
parameters  @p1 nvarchar(max) = SELECT COUNT(*) FROM dbo.readings WHERE value > @P1,@p2 nvarchar(max) = @P1 FLOAT,@P1 floatn(8) = 20
statement   SELECT COUNT(*) FROM dbo.readings WHERE value > @P1

procedure   dbo.usp_get_readings
parameters  @p1 nvarchar(max) = PUMP-00%,@p2 floatn(8) = 10,@p3 intn(4) output = 0
```

An older driver (2009 capture, TDS 7.1) preparing a statement with
`sp_prepexec` and running it again with `sp_execute` by handle. Numbered
procedures like these are the ones other decoders get wrong:

```
procedure   sp_prepexec
proc_id     13
parameters  @p1 intn(4) output = 0,@p2 nvarchar(4000) = @P0 nvarchar(4000),@P1 int,@p3 nvarchar(4000) = select * from test_table_1 where name = @P0 and id = @P1,@p4 nvarchar(4000) = zzz,@p5 intn(4) = 2
statement   select * from test_table_1 where name = @P0 and id = @P1
handle      0

procedure   sp_execute
proc_id     12
parameters  @p1 intn(4) = 2
handle      2
```

A historian's own procedures, with GUIDs, binary and integer parameters:

```
procedure   proc_GetMyExampleTableSampleMetaData
parameters  @p1 uniqueidentifier = 00112233-4455-6677-8899-AABBCCDDEEFF,@p2 null = NULL,@p3 nvarchar(0) = ,@p4 varchar(36) = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij,@p5 intn(4) = 1,@p6 intn(8) = 45,@p7 varbinary(12) = 0x0123456789ABCDEFFEDCBA98,@p8 intn(4) = 108
```

| Field | Meaning |
| --- | --- |
| `procedure` | the name as sent, or `sp_executesql`, `sp_prepexec`, `sp_execute`, `sp_cursoropen` ... for calls made by number |
| `proc_id` | that number, when the call used one |
| `with_recompile` | the WITH RECOMPILE option flag |
| `parameters` | `@name type = value`, one entry per parameter, in order; unnamed parameters are numbered `@p1`, `@p2` ...; `NULL` for nulls; binary as hex; `output` for by-reference parameters |
| `statement` | the SQL text carried by `sp_executesql`, `sp_prepare`, `sp_prepexec`, `sp_prepexecrpc`, `sp_cursoropen`, `sp_cursorprepare` and `sp_cursorprepexec` |
| `handle` | the prepared statement or cursor handle used by `sp_execute`, `sp_cursorfetch` and friends, or returned by `sp_prepexec` |
| `transaction_descriptor` | the transaction the call runs in, 0 when none |

Types are named the way SQL Server does, with the wire nullability variants
(`intn(4)` is a nullable `int`, `floatn(8)` a nullable `float`, `bitn` a
nullable `bit`) and declared lengths, precisions and scales.

Hunting notes: `xp_cmdshell` and other extended procedures called as RPCs;
`sp_executesql` with statements a legitimate application never builds;
parameter values carrying SQL fragments; a `statement` that changes shape
across calls from the same handle; a client that suddenly calls procedures a
historian's UI never uses; `sp_password`, `sp_addsrvrolemember`,
`sp_OACreate`.

## tds_error.log

One line per ERROR token the server sent. Class 11 and above are errors; the
number identifies the condition.

```
is_error  number  state  class  message                                    server_name  procedure  line
T         208     1      16     Invalid object name 'dbo.does_not_exist'.  sqledge01    (empty)    1
T         50000   1      16     custom failure 42                          sqledge01    (empty)    1
T         18456   1      14     Login failed for user 'sa'.                sqledge01    (empty)    1
```

Some numbers to know: 18456 is a failed login (the state byte says why, 8 is
a wrong password, 5 a missing login), 229 and 230 are permission denied, 208
an unknown object (reconnaissance often trips it), 102 and 105 are syntax
errors that follow injection attempts, 2812 a missing procedure, 15281 a
blocked component such as `xp_cmdshell` being disabled, 15151 a login that
cannot be altered.

With `redef TDS::log_info_messages = T;` the INFO tokens (class below 11)
are logged too with `is_error F`: `PRINT` output, "Changed database context
to ...", "Changed language setting to ...".

## tds.log

One line per TDS message in either direction, after reassembly across
packets. It is the skeleton the other logs hang off, and the place to see
sizes, message types, and what came back.

```
ts                        is_orig  msg_type        len   packets  rows  row_count  errors
2026-09-05T23:07:32+0000  T        prelogin        50    1        -     -          -
2026-09-05T23:07:32+0000  F        tabular_result  35    1        0     0          0
2026-09-05T23:07:32+0000  T        login7          248   1        -     -          -
2026-09-05T23:07:32+0000  F        tabular_result  385   1        0     0          0
2026-09-05T23:07:32+0000  T        sql_batch       916   1        -     -          -
2026-09-05T23:07:32+0000  F        tabular_result  26    1        0     0          0
2026-09-05T23:07:32+0000  T        rpc             1175  1        -     -          -
2026-09-05T23:07:32+0000  F        tabular_result  31    1        0     1          0
2026-09-05T23:07:32+0000  T        attention       0     1        -     -          -
```

A `SELECT *` over a table with 60 rows comes back as a four-packet result,
and a bulk load as a large multi-packet message:

```
F  tabular_result  12995  4  60  60  0
T  bulk_load       12110  3  -   -   -
```

| Field | Meaning |
| --- | --- |
| `is_orig` | `T` for client to server |
| `msg_type` | `prelogin`, `login7`, `sql_batch`, `rpc`, `tabular_result`, `attention`, `bulk_load`, `transaction_manager`, `sspi`, `fedauth_token`, `pre_tds7_login` |
| `len`, `packets` | payload bytes and packets the message spanned |
| `rows` | for results: rows returned in this message (ROW and NBCROW tokens) |
| `row_count` | for results: rows affected as reported by DONE tokens with a count |
| `errors` | for results: ERROR tokens in this message |

Hunting notes: large `tabular_result` messages with many `rows` from a host
that normally reads a handful (exfiltration or a scraper), `bulk_load` where
none is expected, `attention` storms (cancelled queries), and any `pre_tds7_login`,
`sspi` or `fedauth_token` messages where the environment does not use them.

## Installation

Requires Zeek 7.0 or newer with Spicy (included in the official builds and
containers) and, for `zkg` to compile the analyzer, a C++ toolchain plus the
libpcap and OpenSSL headers that Zeek's own headers include.

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

A message body the analyzer cannot parse does not take down the connection:
it is reported as a `tds_message_parse_error` weird with the reason, and the
next message is parsed normally.

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

Both work inside the official `zeek/zeek` container once `g++`, `cmake`,
`make`, `libpcap-dev` and `libssl-dev` are installed; CI does exactly that on
Zeek 8.2 and the LTS release.

## License

Apache 2.0, see [LICENSE](LICENSE).
