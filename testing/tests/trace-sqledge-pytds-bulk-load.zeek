# @TEST-DOC: INSERT BULK followed by a multi-packet BULK LOAD message.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-bulk-load.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f ssl.log
# @TEST-EXEC: test ! -f weird.log
