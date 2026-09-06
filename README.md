# zeek-tds

A [Zeek](https://zeek.org) protocol analyzer for Tabular Data Stream, the wire
protocol every client uses to talk to Microsoft SQL Server, written in
[Spicy](https://docs.zeek.org/projects/spicy). It watches port 1433 (or any
port it recognises TDS on) and writes five logs that between them answer the
questions a hunter asks of a database: who connected, from what, as whom, what
they ran, what they called, what broke, and how much came back. A sixth,
opt-in log describes what came back.

## The problem it solves

Picture a plant historian on a segmented network. Dozens of hosts talk to it
over TDS: HMIs polling, engineering workstations poking at configuration, a
reporting server pulling a night's worth of tags, and every so often
something that should not be there. The traffic is easy to see and hard to
read: most of the SQL travels inside remote procedure calls addressed by
number, results come back as typed binary tokens, and a busy client may
multiplex several sessions over one connection.

This analyzer reads TDS 7.x continuously. It reassembles messages across
packets and MARS sessions, decodes both directions, renders every parameter
value by type, follows the connection into TLS when the two sides negotiate
encryption, and tags every line with the Zeek connection `uid`, so the SQL
sits next to `conn.log`, `ssl.log` and everything else Zeek saw. It runs on
Zeek 7 and 8.

## One session, log by log

Everything below is real output from `testing/Traces/sqledge-pytds-workload.pcap`,
a Python client working against Azure SQL Edge. Zeek writes tab-separated
files with a header that names and types the columns. Unset fields are `-`,
empty ones `(empty)`, vectors are comma-separated, and newlines and commas
inside values are escaped as `\x0a` and `\x2c`.

It starts, as everything in Zeek does, with `conn.log`. One TCP connection,
identified by the `uid` that every other line in this walk-through carries:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1788649652.185880	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	tcp	tds	1.180330	84022	34236	S2
```

### tds_login.log: who this is

The first thing the analyzer learns is who is on the line. The client's
PRELOGIN says what driver version it runs and whether it wants encryption; its
LOGIN7 names the machine, the account, the application, the library and the
database; the server answers with its product and version and either a
LOGINACK or an error. All of that lands on one line per connection:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	tds_version	client_version	server_version	client_encryption	server_encryption	encrypted	instance	mars	hostname	username	has_password	integrated_auth	app_name	server_name	library	language	database	attach_db	client_pid	client_prog_ver	client_mac	read_only_intent	odbc	oledb	change_password	server_product	server_product_version	server_tds_version	initial_database	success	error_number	error_message
#types	time	string	addr	port	addr	port	string	string	string	string	string	bool	string	bool	string	string	bool	bool	string	string	string	string	string	string	count	count	string	bool	bool	bool	bool	string	string	string	string	bool	count	string
1788649652.188908	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	7.4	1.0.0.0	15.0.2000.0	not_supported	not_supported	F	MSSQLServer	F	workstation-01	sa	T	F	zeek-tds-corpus	127.0.0.1	Python TDS Library	-	zeektds	-	35535	16777216	02:42:AC:11:00:02	F	T	F	F	Microsoft SQL Server	15.0.2000	7.4	zeektds	T	-	-
```

Reading across: a TDS 7.4 client on a host calling itself `workstation-01`,
process 35535, logging in as `sa` with a password rather than Windows
authentication, from an application named `zeek-tds-corpus` using the Python
TDS library, asking for the `zeektds` database and getting it. Neither side
asked for encryption. The server is Microsoft SQL Server 15.0.2000, which is
the 2019 engine, and the login succeeded. The MAC address is the one LOGIN7
carries as its client id, which is often the only hardware identifier a
database ever sees.

That is already most of a hunt. An `app_name` nobody recognises, `sa` from a
workstation, `password_in_clear` set (the LOGIN7 travelled outside TLS, and
TDS's password obfuscation is a nibble swap and an XOR that anyone on the
wire can undo), a `hostname` that disagrees with DNS for `id.orig_h`, or a driver
that no sanctioned application uses all stand out on this one line.

### tds.log: the rhythm of the conversation

`tds.log` has a line for every message in either direction, after the
analyzer has reassembled it from its packets. It is the skeleton the other
logs hang off. The first lines of our session show the handshake and the
first statements:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	msg_type	len	packets	rows	row_count	errors
#types	time	string	addr	port	addr	port	bool	string	count	count	count	count	count
1788649652.186304	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	prelogin	50	1	-	-	-
1788649652.187838	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	F	tabular_result	35	1	0	0	0
1788649652.188908	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	login7	248	1	-	-	-
1788649652.192683	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	F	tabular_result	385	1	0	0	0
1788649652.193828	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	sql_batch	916	1	-	-	-
1788649652.200528	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	F	tabular_result	26	1	0	0	0
```

`is_orig` is `T` for client to server. When a .NET client multiplexes
sessions over one connection (MARS), the `session` column carries the SMP
session id so concurrent requests and their responses can be paired.
Requests carry a type and a size;
server responses (`tabular_result`) additionally say how many rows they
returned, how many rows the DONE tokens reported affected, and how many
errors they contained. Later in the same session a `SELECT *` comes back as
a four-packet message with sixty rows, and in another trace a bulk load goes
the other way:

```
1788649652.338220	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	F	tabular_result	12995	4	60	60	0
1788649656.417964	ClyAae4GU1BSVUAKl	172.19.0.1	55272	172.19.0.2	1433	T	bulk_load	12110	3	-	-	-
```

Volume lives here: a host that normally reads a handful of rows and one night
reads a million shows up as a `rows` column nobody expected.

### tds_sql_batch.log: what they typed

When the client sends plain SQL it arrives as a SQL batch, and the statement
is logged exactly as sent. Our client creates a table, then runs a
transaction. Transaction manager requests have no SQL text of their own, so
they appear as `<transaction manager: begin>` and friends, which puts the
transaction boundaries and the statements inside them in one place:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	transaction_descriptor	query
#types	time	string	addr	port	addr	port	count	string
1788649652.354631	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	<transaction manager: begin>
1788649652.354934	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	219043332162	UPDATE dbo.readings SET quality = 0 WHERE id = 1
1788649652.355940	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	<transaction manager: commit>
1788649652.357826	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	SELECT * FROM dbo.does_not_exist
1788649652.359079	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	RAISERROR('custom failure %d', 16, 1, 42)
```

The `transaction_descriptor` is the number the server handed out when the
transaction began. Every statement and every procedure call inside that
transaction carries it, in this log and in `tds_rpc.log`, so a transaction can
be reassembled across both. Here is a FreeTDS client from another trace doing
its transaction in SQL rather than through the transaction manager; the
descriptor appears once the server has started it:

```
1788649658.454320	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	0	BEGIN TRAN
1788649658.457145	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	219043332097	SELECT TOP 10 id, tag, value, ts FROM dbo.readings WHERE quality IS NOT NULL
1788649658.464224	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	219043332097	SELECT 42 AS n, N'freetds' AS s
1788649658.468350	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	219043332097	COMMIT TRAN
```

and, from `tds_rpc.log` of the same session, the procedure call that ran
between those statements, inside the same transaction:

```
1788649658.464937	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	219043332097	dbo.usp_get_readings	-	F	@p1 nvarchar(8) = PUMP-01%,@p2 floatn(8) = 0,@p3 intn(8) output = NULL	-	-
```

### tds_rpc.log: what they called

Most application SQL never travels as a batch. Drivers parameterise it and
ship it as a remote procedure call to `sp_executesql`, or prepare it with
`sp_prepexec` and run it again by handle with `sp_execute`. Those procedures
are addressed by number on the wire, which is why other decoders lose them.
Here the analyzer resolves the number, renders every parameter as
`@name type = value`, and lifts the SQL text out of the parameter that carries
it into `statement`:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	transaction_descriptor	procedure	proc_id	with_recompile	parameters	statement	handle
#types	time	string	addr	port	addr	port	count	string	count	bool	vector[string]	string	string
1788649652.343290	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	sp_executesql	10	F	@p1 nvarchar(max) = SELECT COUNT(*) FROM dbo.readings WHERE value > @P1,@p2 nvarchar(max) = @P1 FLOAT,@P1 floatn(8) = 20	SELECT COUNT(*) FROM dbo.readings WHERE value > @P1	-
1788649652.349416	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	0	dbo.usp_get_readings	-	F	@p1 nvarchar(max) = PUMP-00%,@p2 floatn(8) = 10,@p3 intn(4) output = 0	-	-
```

The first line is a parameterised query: the statement, its parameter
declaration, and the value 20 bound to `@P1`. The second is a call to a
user-defined procedure with an `output` parameter, which is how the client
gets a value back. The line is written when the server's response has
arrived, so it also carries what came back: the `output` column holds the
output parameter values the server returned and `return_status` the
procedure's return code. For the same procedure called from a .NET client:

```
procedure      dbo.usp_get_readings
parameters     @tag nvarchar(8) = PUMP-00%,@min floatn(8) = 15,@count intn(4) output = NULL
output         @count intn(4) = 6
return_status  7
``` Types are named the way SQL Server names them, with the
wire's nullable variants: `intn(4)` is a nullable `int`, `floatn(8)` a
nullable `float`.

Earlier in the same session the client inserted sixty rows, each an
`sp_executesql` with fifteen typed parameters. One of them, wrapped for
reading, shows how every TDS data type is rendered as a value rather than as
bytes:

```
@p1 nvarchar(max) = INSERT INTO dbo.readings (tag, value, quality, ts, note, blob, amount, price, flag, guid, d, t, dto, big, xmlcol) VALUES (@P1, @P2, ... @P15)
@p2 nvarchar(max) = @P1 NVARCHAR(MAX),@P2 FLOAT,@P3 INT,@P4 DATETIME2(6),@P5 NVARCHAR(MAX),@P6 VARBINARY(8000),@P7 DECIMAL(8, 4),@P8 DECIMAL(4, 2),@P9 BIT,@P10 UNIQUEIDENTIFIER,@P11 DATE,@P12 TIME(6),@P13 DATETIMEOFFSET(6),@P14 BIGINT,@P15 NVARCHAR(MAX)
@P1 nvarchar(max) = PUMP-001.FLOW
@P2 floatn(8) = 13.5
@P3 intn(4) = 192
@P4 datetime2 = 2026-09-05 12:00:01.000000
@P5 nvarchar(max) = note 1
@P6 varbinary(8000) = 0x0102
@P7 decimaln(8,4) = 1235.5678
@P8 decimaln(4,2) = 99.99
@P9 bitn = true
@P10 uniqueidentifier = 670DBD95-D6FB-4F2F-BD7B-97486DC7F6DB
@P11 date = 2026-09-05
@P12 time = 13:14:15.123456
@P13 datetimeoffset = 2026-09-05 06:02:03.000000 -05:00
@P14 intn(8) = 1099511627777
@P15 nvarchar(max) = <r><a>1</a></r>
```

The `handle` column ties prepared statements together. In a 2009 capture of
an older driver, one connection prepares a statement with `sp_prepexec` (the
handle comes back as the `output` parameter) and a later connection runs a
prepared statement by handle with `sp_execute`:

```
1240877917.918653	C3U1hn4EKed9kvMRdg	10.111.111.111	1111	10.0.0.1	1433	0	sp_prepexec	13	F	@p1 intn(4) output = 0,@p2 nvarchar(4000) = @P0 nvarchar(4000)\x2c@P1 int,@p3 nvarchar(4000) = select * from test_table_1 where name = @P0 and id = @P1,@p4 nvarchar(4000) = zzz,@p5 intn(4) = 2	select * from test_table_1 where name = @P0 and id = @P1	0
1259762401.711921	C06jqe4foQA3lhmMrk	10.111.111.111	5555	10.0.0.1	1433	0	sp_execute	12	F	@p1 intn(4) = 2	-	2
```

The same capture has a historian's own procedures, with GUIDs, binary and
integers rendered in place:

```
1259762400.022561	Cx3zY52d3ABxWRNw0b	10.111.111.111	3333	10.0.0.1	1433	0	p_GetBogusData	-	F	@SearchType intn(1) = 1,@MaxWaitTimeInSeconds intn(4) = 0,@ProcessNegativeAck intn(1) = 0	-	-
```

### tds_error.log: what went wrong

Back in our session, the client asked for a table that does not exist and
then raised an error of its own. The server's ERROR tokens are logged with
their number, state, severity class and text, and their timestamps sit right
after the batches that caused them in `tds_sql_batch.log`:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_error	number	state	class	message	server_name	procedure	line
#types	time	string	addr	port	addr	port	bool	count	count	count	string	string	string	count
1788649652.358791	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	208	1	16	Invalid object name 'dbo.does_not_exist'.	sqledge01	(empty)	1
1788649652.359233	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	50000	1	16	custom failure 42	sqledge01	(empty)	1
```

Error 208 is what reconnaissance trips when it guesses table names; 102 and
105 are the syntax errors that follow injection attempts; 229 and 230 are
permission denied; 15281 is a disabled component such as `xp_cmdshell`
refusing to run. With `redef TDS::log_info_messages = T;` the informational
messages (`PRINT` output, "Changed database context to ...") are logged as
well, with `is_error` set to `F`.

### tds_result.log: what came back

The five logs above are about requests. Results are parsed too, to keep the
token stream aligned and to count rows, and with `redef TDS::log_results = T;`
they get a log of their own: one line per result set with the column names
and types and the row count. That alone tells you which tables and columns a
host reads, without storing the data. With `TDS::result_sample_rows` set, the
first rows are recorded as well, rendered by type and separated by `|`. Both
are off by default because result content is the sensitive part of database
traffic and the volume matches the queries. From our session, with three
sample rows:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	columns	types	rows	sample
#types	time	string	addr	port	addr	port	vector[string]	vector[string]	count	vector[string]
1788649652.338220	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	id,tag,value,quality,ts,note,blob,amount,price,flag,guid,d,t,dto,big,xmlcol	int,nvarchar(64),floatn(8),intn(1),datetime2,varchar(200),varbinary(max),decimaln(12\x2c4),moneyn(8),bitn,uniqueidentifier,date,time,datetimeoffset,intn(8),xml	60	1|PUMP-000.FLOW|NULL|NULL|2026-09-05 12:00:00.000|NULL|0x01|1234.5678|99.9900|false|09BBB7AA-CE65-4CCF-803A-D2CE6C5C7FF5|2026-09-05|13:14:15.1234560|2026-09-05 06:02:03.00 -05:00|1099511627776|<r><a>1</a></r>,2|PUMP-001.FLOW|13.5|-64|2026-09-05 12:00:01.000|note 1|0x0102|1235.5678|99.9900|true|670DBD95-D6FB-4F2F-BD7B-97486DC7F6DB|2026-09-05|13:14:15.1234560|2026-09-05 06:02:03.00 -05:00|1099511627777|<r><a>1</a></r>,3|PUMP-002.FLOW|14.5|-64|2026-09-05 12:00:02.000|note 2|0x010203|1236.5678|99.9900|false|F213C6E0-7DB2-4E72-9342-6D18C2A8E77F|2026-09-05|13:14:15.1234560|2026-09-05 06:02:03.00 -05:00|1099511627778|<r><a>1</a></r>
1788649652.353981	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	id,tag,value	int,nvarchar(64),floatn(8)	5	10|PUMP-009.FLOW|21.5,9|PUMP-008.FLOW|20.5,8|PUMP-007.FLOW|NULL
```

## When the login fails

A second trace has the same client with a wrong password. The server answers
the LOGIN7 with error 18456 instead of a LOGINACK, and `tds_login.log`
records both the attempt and the outcome. The client fields are all there,
because LOGIN7 was sent in the clear:

```
1788649654.371906	CHoXq91qvuIN1IliUc	172.19.0.1	60578	172.19.0.2	1433	7.4	1.0.0.0	15.0.2000.0	not_supported	not_supported	F	MSSQLServer	F	workstation-01	sa	T	F	zeek-tds-badpw	127.0.0.1	Python TDS Library	-	master	-	35535	16777216	02:42:AC:11:00:02	F	T	F	F	-	-	-	-	F	18456	Login failed for user 'sa'.
```

and `tds_error.log` has the error itself:

```
1788649654.385044	CHoXq91qvuIN1IliUc	172.19.0.1	60578	172.19.0.2	1433	T	18456	1	14	Login failed for user 'sa'.	sqledge01	(empty)	1
```

State 1 is what the server tells the client; the server's own log holds the
real reason. A run of these from one source is a password spray.

## When the session is encrypted

Encryption is negotiated in PRELOGIN, and what happens next decides how much
the analyzer sees. Most drivers default to encrypting only the login. Here is
FreeTDS doing that. `conn.log` shows both services on the connection:

```
1788649658.440510	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	tcp	tds,ssl	0.028913	3151	3247	SF
```

The TLS handshake travels inside PRELOGIN packets; the analyzer unwraps it and
hands it to Zeek's SSL analyzer, which writes `ssl.log` for the same `uid`:

```
1788649658.444342	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	x25519	-	F
```

LOGIN7 went through that tunnel, so the client's fields in `tds_login.log`
are empty. But the server answered in the clear, so the product, the database
and the outcome are still known, and `encrypted` is `T`:

```
1788649658.440812	CufcEX3NwEIkMYhrij	172.19.0.1	55276	172.19.0.2	1433	-	9.0.0.0	15.0.2000.0	off	off	T	MSSQLServer	F	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	Microsoft SQL Server	15.0.2000	7.4	zeektds	T	-	-
```

Everything after the login is plaintext again, so the batches and the
procedure call shown earlier for this `uid` were all logged.

When both sides insist on encryption, only the PRELOGIN exchange is visible.
The analyzer forwards every later byte to the SSL analyzer, `tds_login.log`
records the negotiation (`on`, `on`, `encrypted T`), `tds.log` stops after
two lines, and the rest of the session is an `ssl.log` entry with the server
name the client asked for:

```
1788650225.691314	CRYlNv4Pg52RR5gVll	172.19.0.1	61250	172.19.0.2	1433	-	1.0.0.0	15.0.2000.0	on	on	T	MSSQLServer	F	-	-	...
1788650225.696889	CRYlNv4Pg52RR5gVll	172.19.0.1	61250	172.19.0.2	1433	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	x25519	127.0.0.1	F
```

That is the honest limit of passive monitoring, and it is why the plaintext
decoding matters most on the legacy and control-system networks where
encryption is still the exception.

## When the login is a Windows login

With integrated authentication there is no password in LOGIN7. Instead the
client sends an NTLM or Kerberos token, the server answers with a challenge in
an SSPI token, and the client completes the exchange in an SSPI message. The
analyzer recognises the security package from the token and hands the
exchange to Zeek's NTLM or GSSAPI analyzer, so `conn.log` shows `tds,ntlm`
and `ntlm.log` carries the domain, account and workstation for the same
`uid`. `tds_login.log` records the mechanism and the outcome; here a client
tried NTLM against a server that does not trust its domain:

```
hostname        workstation-01
username        (empty)
has_password    F
integrated_auth T
sspi_mechanism  ntlm
success         F
error_number    18452
error_message   Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
```

## How the logs connect

- **`uid`** is on every line of every log, and on `conn.log` and `ssl.log`.
  It is the join key.
- **`ts`** orders requests and responses within a session; an error's
  timestamp follows the batch or call that provoked it, and `tds.log` shows
  the response size and row counts for each request.
- **`transaction_descriptor`** ties `tds_sql_batch.log` and `tds_rpc.log`
  lines to the transaction they ran in, across both logs.
- **`handle`** ties an `sp_execute` or cursor fetch back to the `sp_prepexec`
  or `sp_cursoropen` that created the handle.
- **`is_orig`** in `tds.log` separates the client's messages from the
  server's; the other logs are one-sided by nature (requests in
  `tds_sql_batch` and `tds_rpc`, responses in `tds_error`).

## JSON

Sites that ship logs to Elasticsearch or Splunk usually run Zeek with
`LogAscii::use_json=T`. The same lines then look like this:

```json
{"ts":1788649654.385044,"uid":"CHoXq91qvuIN1IliUc","id.orig_h":"172.19.0.1","id.orig_p":60578,"id.resp_h":"172.19.0.2","id.resp_p":1433,"is_error":true,"number":18456,"state":1,"class":14,"message":"Login failed for user 'sa'.","server_name":"sqledge01","procedure":"","line":1}
```

## What to hunt for

- In `tds_login.log`: accounts, applications and driver libraries that are
  new for a given server; `sa` and other shared logins from workstations;
  `hostname` that does not match DNS; `encrypted F` where policy requires
  encryption; runs of `success F`.
- In `tds_sql_batch.log`: `xp_cmdshell`, `sp_configure`, `OPENROWSET`,
  `BULK INSERT`, `sp_addlogin`, `ALTER LOGIN`, `sp_OACreate`, `xp_dirtree`,
  `WAITFOR DELAY`, `DROP` and `TRUNCATE` against historian tables, and any
  plain SQL from a host that only ever calls procedures.
- In `tds_rpc.log`: extended procedures called as RPCs, `sp_executesql`
  statements an application never builds, parameter values that contain SQL,
  a `statement` that changes shape across calls, procedures a historian's own
  clients never use.
- In `tds_error.log`: 18456 sprays, bursts of 208 and 229, syntax errors that
  follow injection attempts.
- In `tds.log`: results far larger than a host's baseline, unexpected
  `bulk_load`, storms of `attention`.

## Field reference

Every log begins with `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`,
`id.resp_p`.

**tds_login.log**: `tds_version` (client's LOGIN7), `client_version` and
`server_version` (PRELOGIN driver and server versions), `client_encryption`,
`server_encryption` (`off`, `on`, `not_supported`, `required`), `encrypted`,
`instance`, `mars`, `hostname`, `username`, `has_password`,
`integrated_auth`, `app_name`, `server_name` (the name the client connected
to), `library`, `language`, `database`, `attach_db`, `client_pid`,
`client_prog_ver`, `client_mac`, `password_in_clear`, `sspi_mechanism`, `read_only_intent`, `odbc`, `oledb`,
`features`, `user_agent`, `fedauth_library`, `routed_to`,
`change_password`, `server_product`, `server_product_version`,
`server_tds_version`, `initial_database`, `success`, `error_number`,
`error_message`.

**tds_sql_batch.log**: `transaction_descriptor`, `query`.

**tds_rpc.log**: `transaction_descriptor`, `procedure`, `proc_id`,
`with_recompile`, `parameters` (vector of `@name type = value`, `output` for
by-reference parameters, `NULL` for nulls, hex for binary), `statement`,
`handle`, `output` (values returned for output parameters), `return_status`.

**tds_result.log** (opt-in): `columns`, `types`, `rows`, `sample`.

**tds_error.log**: `is_error`, `number`, `state`, `class`, `message`,
`server_name`, `procedure`, `line`.

**tds.log**: `is_orig`, `msg_type` (`prelogin`, `login7`, `sql_batch`,
`rpc`, `tabular_result`, `attention`, `bulk_load`, `transaction_manager`,
`sspi`, `fedauth_token`, `pre_tds7_login`, or `summary`), `len`, `packets`,
`session` (MARS), `rows`, `row_count`, `errors`, and in summary mode
`messages` and `msg_types`.

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

`tds.log` is one line per message, which on a busy database server is a lot
of lines. It stays on by default; two fallbacks exist for loud networks.
`SUMMARY` mode writes one line per connection per interval with totals and a
breakdown of message types (server-to-client types prefixed with `<`):

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	msg_type	len	packets	session	rows	row_count	errors	messages	msg_types
1788649652.186304	CGxaQC26449facJ2Q5	172.19.0.1	60576	172.19.0.2	1433	T	summary	115954	288	-	67	131	2	282	<tabular_result:141,attention:62,login7:1,prelogin:1,rpc:62,sql_batch:11,transaction_manager:4
```

and `DISABLED` turns it off. Every other log has its own switch as well.

```zeek
# Additional ports.
redef TDS::ports += { 14330/tcp };

# tds.log: PER_MESSAGE (default), SUMMARY, or DISABLED.
redef TDS::message_log_mode = TDS::SUMMARY;
redef TDS::summary_interval = 5min;

# The other logs, all on by default.
redef TDS::log_logins = T;
redef TDS::log_sql_batches = T;
redef TDS::log_rpcs = T;
redef TDS::log_rpc_parameters = F;   # keep tds_rpc.log but drop the parameter list
redef TDS::log_errors = T;

# Also log INFO messages (severity below 11) to tds_error.log.
redef TDS::log_info_messages = T;

# Result sets: off by default. Columns and row counts only, or with sample rows.
redef TDS::log_results = T;
redef TDS::result_sample_rows = 3;   # 0-10

# Statements and values are truncated at 1024 bytes; raise or set to 0 for no limit.
# Zeek caps each log field at Log::default_max_field_string_bytes (4096).
redef TDS::max_text = 8192;
redef Log::default_max_field_string_bytes = 65536;
```

## What is and is not decoded

Decoded: packet framing and message reassembly in both directions, including
SMP session multiplexing (MARS); PRELOGIN
options and the encryption negotiation; LOGIN7 (all fields except the
obfuscated password, which is only reported as present); SQL batches with
ALL_HEADERS; RPC requests including numbered procedures, multiple batches, and
parameters of every fixed-length, byte-length, ushort-length, long-length and
partially-length-prefixed type, rendered by type (integers, decimals, money,
floats, strings, binary, GUIDs, all date and time types); transaction manager
requests; the server token stream: LOGINACK, ENVCHANGE, ERROR, INFO, DONE,
RETURNSTATUS, RETURNVALUE, COLMETADATA including Always Encrypted key tables
and crypto metadata, ROW and NBCROW (rendered into tds_result.log when
enabled), FEATUREEXTACK, SSPI, ENVCHANGE routing; LOGIN7 feature extensions
including the client user agent and federated authentication library. Integrated
authentication tokens are handed to Zeek's NTLM and GSSAPI analyzers.

Not decoded: the contents of bulk-load rows; TDS 8.0 (TLS from the first byte, which the SSL
analyzer sees on its own); pre-TDS7 Sybase-style logins.

TDS 7.1 and 7.2+ differ in a few token layouts. The analyzer learns the
version from LOGIN7 or LOGINACK and, when it joins a connection mid-stream,
infers it from whether requests carry ALL_HEADERS. A message body it cannot
parse does not take down the connection: it becomes a
`tds_message_parse_error` weird with the reason, and the next message is
parsed normally.

## Development

The test suite runs Zeek over the captures in `testing/Traces` and compares
every log against a baseline. The captures come from Azure SQL Edge (the SQL
Server 2019 engine, TDS 7.4) driven by pytds, FreeTDS and Microsoft.Data.SqlClient
(with and without MARS), plus a 2009 capture of TDS 7.1 and 7.2 clients;
client identifiers in them are synthetic.

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
