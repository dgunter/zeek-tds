##! SQL Server Browser (SSRP, UDP 1434): instance enumeration and DAC port lookups.
##! One line per request/response pair in ssrp.log. Enumeration is how clients find
##! named instances, and how scanners inventory SQL Servers.

module SSRP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		## broadcast, enumerate, instance or dac.
		request: string &log;
		## Instance name asked for (instance and dac requests).
		instance: string &log &optional;
		## Instances the server answered with, as "ServerName\Instance version tcp/port".
		instances: vector of string &log &optional;
		## Dedicated admin connection port returned for a dac request.
		dac_port: count &log &optional;
		## The server answered.
		answered: bool &log &default=F;
	};

	global log_ssrp: event(rec: Info);
	global log_policy: Log::PolicyHook;
}

redef record connection += {
	ssrp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_ssrp, $path="ssrp", $policy=log_policy]);
	}

function emit(c: connection)
	{
	if ( ! c?$ssrp )
		return;
	Log::write(LOG, c$ssrp);
	delete c$ssrp;
	}

event SSRP::request(c: connection, kind: string, instance: string)
	{
	emit(c);
	c$ssrp = Info($ts=network_time(), $uid=c$uid, $id=c$id, $request=kind);
	if ( instance != "" )
		c$ssrp$instance = instance;
	}

# "ServerName;X;InstanceName;Y;IsClustered;No;Version;15.0.2000.1574;tcp;1433;;" per instance.
function parse_instances(text: string): vector of string
	{
	local out: vector of string = vector();
	for ( _, entry in split_string(text, /;;/) )
		{
		local kv = split_string(entry, /;/);
		local fields: table[string] of string = table();
		local i = 0;
		while ( i + 1 < |kv| )
			{
			fields[kv[i]] = kv[i + 1];
			i += 2;
			}
		if ( "InstanceName" !in fields )
			next;
		local desc = fmt("%s\\%s", "ServerName" in fields ? fields["ServerName"] : "?", fields["InstanceName"]);
		if ( "Version" in fields )
			desc += fmt(" %s", fields["Version"]);
		if ( "tcp" in fields )
			desc += fmt(" tcp/%s", fields["tcp"]);
		if ( "IsClustered" in fields && fields["IsClustered"] == "Yes" )
			desc += " clustered";
		out += desc;
		}
	return out;
	}

event SSRP::response(c: connection, text: string, dac_port: count)
	{
	if ( ! c?$ssrp )
		c$ssrp = Info($ts=network_time(), $uid=c$uid, $id=c$id, $request="unsolicited");
	c$ssrp$answered = T;
	if ( dac_port > 0 )
		c$ssrp$dac_port = dac_port;
	if ( text != "" )
		c$ssrp$instances = parse_instances(text);
	emit(c);
	}

event connection_state_remove(c: connection)
	{
	emit(c);
	}
