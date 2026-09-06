##! Detections on top of the TDS logs. Each raises a Zeek notice and can be tuned or
##! switched off with the redefs below. See docs/attack-coverage.md for how they map
##! to ATT&CK techniques.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./main

module TDS;

export {
	redef enum Notice::Type += {
		## Repeated failed logins from one client (T1110 Brute Force).
		Login_Bruteforce,
		## A statement, procedure name or parameter matched TDS::dangerous_patterns:
		## command execution, registry and file access, persistence, privilege and
		## account changes, linked-server and bulk data movement.
		Dangerous_Statement,
		## One client probed several SQL servers with PRELOGIN but never logged in
		## (T1046 Network Service Discovery).
		Scan,
		## A result set larger than TDS::large_result_rows or TDS::large_result_bytes
		## (T1030 / T1041 exfiltration, T1213 data from information repositories).
		Large_Result,
		## A bulk load into the server (T1105 Ingress Tool Transfer, data staging).
		Bulk_Load,
		## A password was sent in a LOGIN7 outside TLS.
		Cleartext_Password,
		## An application name or driver library not seen before against this server
		## (T1078 Valid Accounts used from new tooling).
		New_Application,
	};

	## Failed logins from one source address within bruteforce_interval that raise
	## Login_Bruteforce.
	const bruteforce_threshold = 10.0 &redef;
	const bruteforce_interval = 10min &redef;

	## Distinct servers one source may PRELOGIN-probe without logging in before Scan
	## is raised.
	const scan_threshold = 5.0 &redef;
	const scan_interval = 10min &redef;

	## Statement, procedure and parameter text that raises Dangerous_Statement.
	## Matched case-insensitively against SQL batches, RPC procedure names and RPC
	## parameter values (which is where sp_executesql carries its SQL).
	const dangerous_patterns =
		  /xp_cmdshell/
		| /sp_oacreate/ | /sp_oamethod/ | /sp_oagetproperty/
		| /xp_regread/ | /xp_regwrite/ | /xp_regdeletekey/ | /xp_regenumvalues/ | /xp_instance_reg/
		| /xp_dirtree/ | /xp_fileexist/ | /xp_subdirs/ | /xp_getfiledetails/ | /xp_servicecontrol/
		| /sp_addextendedproc/ | /sp_execute_external_script/ | /sp_replwritetovarbin/
		| /sp_configure[^;]*(xp_cmdshell|ole automation|clr enabled|show advanced|ad hoc distributed|external scripts)/
		| /openrowset/ | /opendatasource/ | /bulk insert/ | /sp_addlinkedserver/ | /sp_addlinkedsrvlogin/
		| /create assembly/ | /sp_procoption/ | /trustworthy on/ | /sp_setapprole/
		| /sp_password/ | /alter login/ | /create login/ | /sp_addlogin/ | /sp_addsrvrolemember/
		| /alter server role[^;]*add member/ | /sp_addrolemember/ | /sp_grantlogin/ | /xp_loginconfig/
		| /sys\.sql_logins/ | /password_hash/ | /sys\.syslogins/ | /master\.\.sysxlogins/
		| /waitfor delay/ | /sp_add_job/ | /sp_add_jobstep/ | /sp_start_job/
		| /backup database[^;]*to disk *= *'\\\\/ | /sp_msforeachdb/ &redef;

	## Result sets at or above these sizes raise Large_Result.
	const large_result_rows = 100000 &redef;
	const large_result_bytes = 50000000 &redef;

	## Raise Bulk_Load for BULK LOAD messages (off: bulk loads are routine for ETL).
	const detect_bulk_load = F &redef;

	## Raise Cleartext_Password when a LOGIN7 with a password is seen outside TLS
	## (off: still common on legacy and control-system networks; the log has it).
	const detect_cleartext_password = F &redef;

	## Raise New_Application the first time an application name or library is seen
	## against a server (off: every application fires once after Zeek starts).
	const detect_new_applications = F &redef;
	const new_application_memory = 7days &redef;
}

# -- Brute force --------------------------------------------------------------------------

event zeek_init() &priority=5
	{
	local r1 = SumStats::Reducer($stream="tds.login.failure", $apply=set(SumStats::SUM, SumStats::UNIQUE),
	                             $unique_max=double_to_count(scan_threshold + 2));
	SumStats::create([$name="tds-login-bruteforce",
	                  $epoch=bruteforce_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{ return result["tds.login.failure"]$sum; },
	                  $threshold=bruteforce_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["tds.login.failure"];
	                  	NOTICE([$note=Login_Bruteforce, $src=key$host,
	                  	        $msg=fmt("%s failed %d SQL Server logins in %s against %d server(s)",
	                  	                 key$host, double_to_count(r$sum), bruteforce_interval, r$unique),
	                  	        $identifier=cat(key$host)]);
	                  	}]);

	local r2 = SumStats::Reducer($stream="tds.scan", $apply=set(SumStats::UNIQUE),
	                             $unique_max=double_to_count(scan_threshold + 2));
	SumStats::create([$name="tds-scan",
	                  $epoch=scan_interval,
	                  $reducers=set(r2),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{ return result["tds.scan"]$unique + 0.0; },
	                  $threshold=scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	NOTICE([$note=Scan, $src=key$host,
	                  	        $msg=fmt("%s probed %d SQL Servers with PRELOGIN without logging in, in %s",
	                  	                 key$host, result["tds.scan"]$unique, scan_interval),
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event TDS::log_tds_login(rec: LoginInfo)
	{
	if ( rec?$success && ! rec$success )
		SumStats::observe("tds.login.failure", [$host=rec$id$orig_h], [$str=cat(rec$id$resp_h)]);

	if ( detect_cleartext_password && rec$password_in_clear )
		NOTICE([$note=Cleartext_Password, $id=rec$id, $uid=rec$uid,
		        $msg=fmt("%s sent a SQL Server password outside TLS to %s as %s",
		                 rec$id$orig_h, rec$id$resp_h, rec?$username ? rec$username : "?"),
		        $sub=rec?$app_name ? rec$app_name : "",
		        $identifier=cat(rec$id$orig_h, rec$id$resp_h)]);
	}

# -- Scanning ------------------------------------------------------------------------------

hook TDS::finalize_tds(c: connection) &priority=10
	{
	if ( ! c?$tds )
		return;
	local l = c$tds$login;
	# PRELOGIN answered, but no LOGIN7, no TLS, no login result: a probe.
	if ( l?$client_version && ! l?$tds_version && ! l$encrypted && ! l?$success && ! l?$integrated_auth )
		SumStats::observe("tds.scan", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
	}

# -- Dangerous statements ----------------------------------------------------------------

function check_text(c: connection, kind: string, text: string)
	{
	local lowered = to_lower(text);
	if ( dangerous_patterns !in lowered )
		return;
	local hit = match_pattern(lowered, dangerous_patterns);
	NOTICE([$note=Dangerous_Statement, $conn=c,
	        $msg=fmt("%s from %s to %s matched \"%s\": %s", kind, c$id$orig_h, c$id$resp_h,
	                 hit$str, truncate(text)),
	        $sub=hit$str,
	        $identifier=cat(c$id$orig_h, c$id$resp_h, hit$str)]);
	}

event TDS::sql_batch(c: connection, transaction_descriptor: count, query: string) &priority=-3
	{
	check_text(c, "SQL batch", query);
	}

event TDS::rpc_batch(c: connection, procedure: string, proc_id: count, option_flags: count) &priority=-3
	{
	check_text(c, "RPC", procedure);
	}

event TDS::rpc_parameter(c: connection, name: string, status: count, typ: string, value: string) &priority=-3
	{
	check_text(c, "RPC parameter", value);
	}

# -- Volume --------------------------------------------------------------------------------

event TDS::message(c: connection, is_orig: bool, msg_type: count, len: count, packets: count, sid: count) &priority=10
	{
	if ( ! c?$tds )
		return;

	if ( ! is_orig && msg_type == 4 && (c$tds$rows >= large_result_rows || len >= large_result_bytes) )
		NOTICE([$note=Large_Result, $conn=c,
		        $msg=fmt("%s received a %d-row, %d-byte result from %s", c$id$orig_h, c$tds$rows, len, c$id$resp_h),
		        $n=c$tds$rows, $identifier=cat(c$id$orig_h, c$id$resp_h)]);

	if ( detect_bulk_load && is_orig && msg_type == 7 )
		NOTICE([$note=Bulk_Load, $conn=c,
		        $msg=fmt("%s bulk-loaded %d bytes into %s", c$id$orig_h, len, c$id$resp_h),
		        $identifier=cat(c$id$orig_h, c$id$resp_h)]);
	}

# -- New applications ----------------------------------------------------------------------

global known_applications: set[addr, string] &create_expire=new_application_memory;

event TDS::log_tds_login(rec: LoginInfo) &priority=-3
	{
	if ( ! detect_new_applications || ! rec?$app_name )
		return;
	local app = fmt("%s / %s", rec$app_name, rec?$library ? rec$library : "?");
	if ( [rec$id$resp_h, app] in known_applications )
		return;
	add known_applications[rec$id$resp_h, app];
	NOTICE([$note=New_Application, $id=rec$id, $uid=rec$uid,
	        $msg=fmt("first login to %s from application %s (user %s, host %s)", rec$id$resp_h, app,
	                 rec?$username ? rec$username : "?", rec?$hostname ? rec$hostname : "?"),
	        $sub=app, $identifier=cat(rec$id$resp_h, app)]);
	}
