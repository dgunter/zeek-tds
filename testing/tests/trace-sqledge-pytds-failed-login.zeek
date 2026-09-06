# @TEST-DOC: Login rejected with error 18456: tds_login.log records the failure.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-failed-login.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_error.log
# @TEST-EXEC: test ! -f tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f ssl.log
# @TEST-EXEC: test ! -f weird.log
