##! Logs for Microsoft SQL Server's Tabular Data Stream (TDS) protocol.
##!
##! Streams:
##!   tds.log            one line per reassembled TDS message
##!   tds_login.log      one line per connection: PRELOGIN, LOGIN7 and the server's answer
##!   tds_sql_batch.log  every SQL batch, with its transaction descriptor
##!   tds_rpc.log        every remote procedure call, with rendered parameters
##!   tds_error.log      ERROR (and optionally INFO) tokens from the server

@load base/protocols/conn/removal-hooks

module TDS;

export {
	redef enum Log::ID += { LOG, LOGIN_LOG, SQL_BATCH_LOG, RPC_LOG, ERROR_LOG };

	## Ports TDS is registered on, in addition to detection by signature.
	const ports = { 1433/tcp } &redef;

	## Also log INFO tokens (severity below 11) to tds_error.log.
	const log_info_messages = F &redef;

	## Per-log switches. tds_login, tds_sql_batch, tds_rpc and tds_error are on by
	## default; each can be turned off on a busy network.
	const log_logins = T &redef;
	const log_sql_batches = T &redef;
	const log_rpcs = T &redef;
	const log_errors = T &redef;
	## Include the rendered parameter list in tds_rpc.log (the widest column there).
	const log_rpc_parameters = T &redef;

	## How tds.log records messages. PER_MESSAGE writes one line per TDS message;
	## SUMMARY writes one line per connection per :zeek:see:`TDS::summary_interval`
	## with totals; DISABLED writes nothing.
	type MessageLogMode: enum { PER_MESSAGE, SUMMARY, DISABLED };
	const message_log_mode = PER_MESSAGE &redef;
	const summary_interval = 1min &redef;

	## Truncate logged SQL text, messages and parameter values to this many bytes
	## (0 = no limit). Zeek itself caps a log field at
	## :zeek:see:`Log::default_max_field_string_bytes` (4096 by default), so raise that
	## too if you want longer statements in full.
	const max_text = 1024 &redef;

	## Names of the packet types, [MS-TDS] 2.2.3.1.1.
	const packet_types: table[count] of string = {
		[1] = "sql_batch", [2] = "pre_tds7_login", [3] = "rpc", [4] = "tabular_result",
		[6] = "attention", [7] = "bulk_load", [8] = "fedauth_token",
		[14] = "transaction_manager", [16] = "login7", [17] = "sspi", [18] = "prelogin",
	} &default = function(t: count): string { return fmt("type_%d", t); };

	const encryption_names: table[count] of string = {
		[0] = "off", [1] = "on", [2] = "not_supported", [3] = "required",
		[0x80] = "off_client_cert", [0x81] = "on_client_cert", [0x83] = "required_client_cert",
	} &default = function(e: count): string { return fmt("0x%02x", e); };

	const env_change_types: table[count] of string = {
		[1] = "database", [2] = "language", [3] = "charset", [4] = "packet_size",
		[5] = "unicode_sort_locale", [6] = "unicode_comparison_flags", [7] = "sql_collation",
		[8] = "begin_transaction", [9] = "commit_transaction", [10] = "rollback_transaction",
		[11] = "enlist_dtc_transaction", [12] = "defect_transaction", [13] = "mirroring_partner",
		[15] = "promote_transaction", [16] = "transaction_manager_address", [17] = "transaction_ended",
		[18] = "reset_connection", [19] = "user_instance", [20] = "routing",
	} &default = function(t: count): string { return fmt("type_%d", t); };

	const transaction_request_types: table[count] of string = {
		[0] = "get_dtc_address", [1] = "propagate_transaction", [5] = "begin", [6] = "promote",
		[7] = "commit", [8] = "rollback", [9] = "save",
	} &default = function(t: count): string { return fmt("type_%d", t); };

	## Special stored procedures whose SQL text arrives as a parameter, and which
	## parameter (1-based) carries it. Used to fill ``statement`` in tds_rpc.log.
	const statement_parameter: table[string] of count = {
		["sp_executesql"] = 1, ["sp_prepare"] = 3, ["sp_prepexec"] = 3, ["sp_prepexecrpc"] = 3,
		["sp_cursoropen"] = 2, ["sp_cursorprepare"] = 3, ["sp_cursorprepexec"] = 4,
	};

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		## Direction: T for client to server.
		is_orig: bool &log;
		## Packet type of the message.
		msg_type: string &log;
		## Payload bytes in the message.
		len: count &log;
		## Packets the message spanned.
		packets: count &log;
		## MARS session id when the connection multiplexes sessions (SMP).
		session: count &log &optional;
		## For server responses: rows returned in this message.
		rows: count &log &optional;
		## For server responses: rows affected as reported by DONE tokens.
		row_count: count &log &optional;
		## For server responses: ERROR tokens in this message.
		errors: count &log &optional;
		## SUMMARY mode: number of messages the line covers (msg_type is "summary",
		## len and packets are totals, rows/row_count/errors are totals over responses).
		messages: count &log &optional;
		## SUMMARY mode: message types seen in the window, with counts; "<" marks
		## server-to-client types.
		msg_types: string &log &optional;
	};

	type LoginInfo: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		## Client TDS version from LOGIN7.
		tds_version: string &log &optional;
		## Client library version announced in PRELOGIN (major.minor.build.subbuild).
		client_version: string &log &optional;
		## Server version announced in PRELOGIN.
		server_version: string &log &optional;
		## Encryption requested by the client and answered by the server.
		client_encryption: string &log &optional;
		server_encryption: string &log &optional;
		## Whether the session went on to TLS.
		encrypted: bool &log &default=F;
		## Instance name requested in PRELOGIN.
		instance: string &log &optional;
		mars: bool &log &optional;
		hostname: string &log &optional;
		username: string &log &optional;
		## A password was supplied (SQL authentication).
		has_password: bool &log &optional;
		## Integrated (Windows) authentication requested.
		integrated_auth: bool &log &optional;
		## Security package of the integrated authentication exchange: ntlm or gssapi
		## (Kerberos/SPNEGO). The exchange itself is handed to Zeek's NTLM and GSSAPI
		## analyzers, so ntlm.log and kerberos.log carry the account details.
		sspi_mechanism: string &log &optional;
		app_name: string &log &optional;
		server_name: string &log &optional;
		## Client interface library (ODBC, OLEDB, .NET SqlClient, jTDS ...).
		library: string &log &optional;
		language: string &log &optional;
		database: string &log &optional;
		attach_db: string &log &optional;
		client_pid: count &log &optional;
		client_prog_ver: count &log &optional;
		client_mac: string &log &optional;
		read_only_intent: bool &log &optional;
		odbc: bool &log &optional;
		oledb: bool &log &optional;
		change_password: bool &log &optional;
		## From the server's LOGINACK.
		server_product: string &log &optional;
		server_product_version: string &log &optional;
		server_tds_version: string &log &optional;
		## Database the session landed in (ENVCHANGE).
		initial_database: string &log &optional;
		## Login succeeded (LOGINACK seen) or failed (ERROR before LOGINACK).
		success: bool &log &optional;
		error_number: count &log &optional;
		error_message: string &log &optional;
	};

	type SQLBatchInfo: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		transaction_descriptor: count &log;
		query: string &log;
	};

	type RPCInfo: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		transaction_descriptor: count &log;
		## Procedure name, or the well-known name of a numbered procedure.
		procedure: string &log;
		## Numeric id when the procedure was addressed by number.
		proc_id: count &log &optional;
		with_recompile: bool &log;
		## Parameters as ``@name type = value``.
		parameters: vector of string &log;
		## SQL text carried as a parameter by sp_executesql, sp_prepexec and friends.
		statement: string &log &optional;
		## Prepared statement or cursor handle when the procedure uses one.
		handle: string &log &optional;
	};

	type ErrorInfo: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		## F for INFO tokens.
		is_error: bool &log;
		number: count &log;
		state: count &log;
		## Severity class; 11 and above are errors.
		class: count &log;
		message: string &log;
		server_name: string &log;
		procedure: string &log;
		line: count &log;
	};

	## State kept per connection.
	type State: record {
		login: LoginInfo;
		## The RPC batches of the request currently being parsed.
		rpc: vector of RPCInfo;
		## Message-level counters filled from the token stream.
		rows: count &default=0;
		row_count: count &default=0;
		errors: count &default=0;
		## Login not yet acknowledged.
		login_pending: bool &default=F;
		## The connection uses MARS session multiplexing.
		mars: bool &default=F;
		login_logged: bool &default=F;
		## SUMMARY mode accumulator for tds.log.
		summary: Info &optional;
		summary_types: table[string] of count &optional;
	};

	global log_tds: event(rec: Info);
	global log_tds_login: event(rec: LoginInfo);
	global log_tds_sql_batch: event(rec: SQLBatchInfo);
	global log_tds_rpc: event(rec: RPCInfo);
	global log_tds_error: event(rec: ErrorInfo);

	global log_policy: Log::PolicyHook;
	global log_policy_login: Log::PolicyHook;
	global log_policy_sql_batch: Log::PolicyHook;
	global log_policy_rpc: Log::PolicyHook;
	global log_policy_error: Log::PolicyHook;

	global finalize_tds: Conn::RemovalHook;
}

redef record connection += {
	tds: State &optional;
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_tds, $path="tds", $policy=log_policy]);
	Log::create_stream(LOGIN_LOG, [$columns=LoginInfo, $ev=log_tds_login, $path="tds_login", $policy=log_policy_login]);
	Log::create_stream(SQL_BATCH_LOG, [$columns=SQLBatchInfo, $ev=log_tds_sql_batch, $path="tds_sql_batch", $policy=log_policy_sql_batch]);
	Log::create_stream(RPC_LOG, [$columns=RPCInfo, $ev=log_tds_rpc, $path="tds_rpc", $policy=log_policy_rpc]);
	Log::create_stream(ERROR_LOG, [$columns=ErrorInfo, $ev=log_tds_error, $path="tds_error", $policy=log_policy_error]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_TDS, ports);
	}

function truncate(s: string): string
	{
	if ( max_text > 0 && |s| > max_text )
		return s[:max_text];
	return s;
	}

hook set_session(c: connection)
	{
	if ( c?$tds )
		return;

	c$tds = State($login=LoginInfo($ts=network_time(), $uid=c$uid, $id=c$id), $rpc=vector());
	Conn::register_removal_hook(c, finalize_tds);
	}

function emit_login(c: connection)
	{
	if ( ! c?$tds || c$tds$login_logged )
		return;

	local l = c$tds$login;
	# Nothing to say about a connection that never got to a login exchange.
	if ( ! l?$tds_version && ! l?$client_version && ! l?$server_product )
		return;

	if ( log_logins )
		Log::write(LOGIN_LOG, l);
	c$tds$login_logged = T;
	}

function flush_summary(c: connection)
	{
	if ( ! c?$tds || ! c$tds?$summary )
		return;

	local s = c$tds$summary;
	local parts: vector of string = vector();
	for ( t, n in c$tds$summary_types )
		parts += fmt("%s:%d", t, n);
	sort(parts, strcmp);
	s$msg_types = join_string_vec(parts, ",");
	Log::write(LOG, s);
	delete c$tds$summary;
	delete c$tds$summary_types;
	}

event TDS::flush_summary_timer(c: connection)
	{
	if ( ! connection_exists(c$id) )
		return;
	flush_summary(c);
	}

function summarize(c: connection, info: Info)
	{
	if ( ! c$tds?$summary )
		{
		c$tds$summary = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=T,
		                     $msg_type="summary", $len=0, $packets=0, $messages=0,
		                     $rows=0, $row_count=0, $errors=0);
		c$tds$summary_types = table();
		schedule summary_interval { TDS::flush_summary_timer(c) };
		}

	local s = c$tds$summary;
	s$len += info$len;
	s$packets += info$packets;
	s$messages += 1;
	local key = (info$is_orig ? "" : "<") + info$msg_type;
	if ( key !in c$tds$summary_types )
		c$tds$summary_types[key] = 0;
	c$tds$summary_types[key] += 1;
	if ( info?$rows )
		{
		s$rows += info$rows;
		s$row_count += info$row_count;
		s$errors += info$errors;
		}
	}

event TDS::message(c: connection, is_orig: bool, msg_type: count, len: count, packets: count, sid: count)
	{
	hook set_session(c);

	local info = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
	                  $msg_type=packet_types[msg_type], $len=len, $packets=packets);
	if ( c$tds$mars )
		info$session = sid;

	if ( ! is_orig && msg_type == 4 )
		{
		info$rows = c$tds$rows;
		info$row_count = c$tds$row_count;
		info$errors = c$tds$errors;
		}

	c$tds$rows = 0;
	c$tds$row_count = 0;
	c$tds$errors = 0;

	if ( message_log_mode == PER_MESSAGE )
		Log::write(LOG, info);
	else if ( message_log_mode == SUMMARY )
		summarize(c, info);
	}

event TDS::sspi(c: connection, is_orig: bool, mechanism: string, len: count)
	{
	hook set_session(c);
	c$tds$login$integrated_auth = T;
	if ( mechanism != "" && ! c$tds$login?$sspi_mechanism )
		c$tds$login$sspi_mechanism = mechanism;
	}

event TDS::smp_session(c: connection, is_orig: bool, sid: count)
	{
	hook set_session(c);
	c$tds$mars = T;
	c$tds$login$mars = T;
	}

event TDS::response(c: connection, rows: count, row_count: count, errors: count)
	{
	hook set_session(c);
	c$tds$rows = rows;
	c$tds$row_count = row_count;
	c$tds$errors = errors;
	}

event TDS::prelogin(c: connection, is_orig: bool, version: string, encryption: count, instance: string,
                    thread_id: count, mars: bool, fedauth_required: bool, has_nonce: bool, has_trace_id: bool)
	{
	hook set_session(c);
	local l = c$tds$login;

	if ( is_orig )
		{
		l$client_version = version;
		l$client_encryption = encryption_names[encryption];
		if ( instance != "" )
			l$instance = instance;
		l$mars = mars;
		}
	else
		{
		l$server_version = version;
		l$server_encryption = encryption_names[encryption];
		}
	}

event TDS::tls_record(c: connection, is_orig: bool, typ: count, len: count)
	{
	hook set_session(c);
	c$tds$login$encrypted = T;
	}

event TDS::login7(c: connection, tds_version: string, packet_size: count, client_prog_ver: count,
                  client_pid: count, flags1: count, flags2: count, type_flags: count, flags3: count,
                  hostname: string, username: string, has_password: bool, app_name: string,
                  server_name: string, library: string, language: string, database: string,
                  attach_db: string, has_sspi: bool, change_password: bool, client_mac: string)
	{
	hook set_session(c);
	local l = c$tds$login;

	l$ts = network_time();
	l$tds_version = tds_version;
	l$client_pid = client_pid;
	l$client_prog_ver = client_prog_ver;
	l$hostname = hostname;
	l$username = username;
	l$has_password = has_password;
	l$integrated_auth = (flags2 & 0x80) != 0 || has_sspi;
	l$odbc = (flags2 & 0x02) != 0;
	l$oledb = (type_flags & 0x10) != 0;
	l$read_only_intent = (type_flags & 0x20) != 0;
	l$change_password = change_password;
	l$app_name = app_name;
	l$server_name = server_name;
	l$library = library;
	if ( language != "" )
		l$language = language;
	if ( database != "" )
		l$database = database;
	if ( attach_db != "" )
		l$attach_db = attach_db;
	l$client_mac = client_mac;
	c$tds$login_pending = T;
	}

event TDS::login_ack(c: connection, interface: count, tds_version: string, prog_name: string, prog_version: string)
	{
	hook set_session(c);
	local l = c$tds$login;
	l$server_product = prog_name;
	l$server_product_version = prog_version;
	l$server_tds_version = tds_version;
	l$success = T;
	c$tds$login_pending = F;
	}

event TDS::env_change(c: connection, typ: count, new_value: string, old_value: string)
	{
	hook set_session(c);
	if ( typ == 1 && ! c$tds$login?$initial_database )
		c$tds$login$initial_database = new_value;
	}

event TDS::error_info(c: connection, is_error: bool, number: count, state: count, class: count,
                      message: string, server_name: string, procedure: string, line: count)
	{
	hook set_session(c);

	if ( is_error && c$tds$login_pending && ! c$tds$login?$success )
		{
		c$tds$login$success = F;
		c$tds$login$error_number = number;
		c$tds$login$error_message = message;
		c$tds$login_pending = F;
		}

	if ( ! log_errors || (! is_error && ! log_info_messages) )
		return;

	Log::write(ERROR_LOG, ErrorInfo($ts=network_time(), $uid=c$uid, $id=c$id, $is_error=is_error,
	                                $number=number, $state=state, $class=class, $message=truncate(message),
	                                $server_name=server_name, $procedure=procedure, $line=line));
	}

event TDS::sql_batch(c: connection, transaction_descriptor: count, query: string)
	{
	hook set_session(c);
	if ( ! log_sql_batches )
		return;
	Log::write(SQL_BATCH_LOG, SQLBatchInfo($ts=network_time(), $uid=c$uid, $id=c$id,
	                                       $transaction_descriptor=transaction_descriptor,
	                                       $query=truncate(query)));
	}

event TDS::transaction_manager_request(c: connection, request_type: count)
	{
	hook set_session(c);
	if ( ! log_sql_batches )
		return;
	Log::write(SQL_BATCH_LOG, SQLBatchInfo($ts=network_time(), $uid=c$uid, $id=c$id,
	                                       $transaction_descriptor=0,
	                                       $query=fmt("<transaction manager: %s>", transaction_request_types[request_type])));
	}

# Spicy raises unit events when a unit completes, so within one RPC message Zeek sees
# rpc_batch, then that batch's rpc_parameter events, then the next batch ... and finally
# rpc_request for the whole message, which carries the transaction descriptor and closes
# the request. Batches are logged at that point.
event TDS::rpc_batch(c: connection, procedure: string, proc_id: count, option_flags: count) &priority=5
	{
	hook set_session(c);
	local r = RPCInfo($ts=network_time(), $uid=c$uid, $id=c$id, $transaction_descriptor=0,
	                  $procedure=procedure, $with_recompile=(option_flags & 0x01) != 0,
	                  $parameters=vector());
	if ( proc_id > 0 )
		r$proc_id = proc_id;
	c$tds$rpc += r;
	}

event TDS::rpc_parameter(c: connection, name: string, status: count, typ: string, value: string) &priority=5
	{
	hook set_session(c);
	if ( |c$tds$rpc| == 0 )
		return;

	local r = c$tds$rpc[|c$tds$rpc| - 1];
	local n = |r$parameters| + 1;
	local label = name == "" ? fmt("@p%d", n) : name;
	local rendered = truncate(value);
	r$parameters += fmt("%s %s%s = %s", label, typ, (status & 0x01) != 0 ? " output" : "", rendered);

	if ( r$procedure in statement_parameter && statement_parameter[r$procedure] == n )
		r$statement = rendered;
	# sp_execute, sp_cursorexecute etc. address a prepared handle in their first parameter;
	# sp_prepexec and sp_cursoropen return one as an output parameter.
	if ( n == 1 && (r$procedure in set("sp_execute", "sp_prepexec", "sp_prepare", "sp_unprepare",
	                                    "sp_cursorexecute", "sp_cursorfetch", "sp_cursorclose",
	                                    "sp_cursoroption", "sp_cursor", "sp_cursorunprepare")) )
		r$handle = rendered;
	}

event TDS::rpc_request(c: connection, transaction_descriptor: count) &priority=-5
	{
	hook set_session(c);
	for ( i in c$tds$rpc )
		{
		c$tds$rpc[i]$transaction_descriptor = transaction_descriptor;
		if ( ! log_rpc_parameters )
			c$tds$rpc[i]$parameters = vector();
		if ( log_rpcs )
			Log::write(RPC_LOG, c$tds$rpc[i]);
		}
	c$tds$rpc = vector();
	}

event TDS::return_value(c: connection, name: string, typ: string, value: string)
	{
	}

hook finalize_tds(c: connection)
	{
	emit_login(c);
	flush_summary(c);
	}

# Log the login as soon as the server has answered it, so long-lived sessions
# show up without waiting for the connection to end.
event TDS::login_ack(c: connection, interface: count, tds_version: string, prog_name: string, prog_version: string) &priority=-5
	{
	emit_login(c);
	}

event TDS::error_info(c: connection, is_error: bool, number: count, state: count, class: count,
                      message: string, server_name: string, procedure: string, line: count) &priority=-5
	{
	if ( c?$tds && c$tds$login?$success && ! c$tds$login$success )
		emit_login(c);
	}
