# @TEST-DOC: pytds 7.4 session: PRELOGIN, LOGIN7 with SQL authentication, two SQL batches, LOGINACK and ENVCHANGE.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-setup.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f ssl.log
# @TEST-EXEC: test ! -f weird.log
