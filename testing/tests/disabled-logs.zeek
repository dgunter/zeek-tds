# @TEST-DOC: Every log can be switched off.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test ! -f tds.log
# @TEST-EXEC: test ! -f tds_login.log
# @TEST-EXEC: test ! -f tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f tds_error.log

redef TDS::message_log_mode = TDS::DISABLED;
redef TDS::log_logins = F;
redef TDS::log_sql_batches = F;
redef TDS::log_rpcs = F;
redef TDS::log_errors = F;
