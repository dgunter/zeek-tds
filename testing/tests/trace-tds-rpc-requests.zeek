# @TEST-DOC: 2009 capture (TDS 7.1 and 7.2 clients, no LOGIN7): sp_prepexec, sp_execute, sp_executesql and named procedures, including the numbered procedures other analyzers misparse.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tds-rpc-requests.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: test ! -f tds_login.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f ssl.log
# @TEST-EXEC: test ! -f weird.log

