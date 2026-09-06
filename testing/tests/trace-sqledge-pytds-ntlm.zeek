# @TEST-DOC: Integrated authentication: LOGIN7 carries an NTLMSSP negotiate token, which is handed to Zeek's NTLM analyzer (conn.log shows tds,ntlm); the server rejects the login with 18452 and tds_login.log records mechanism and failure.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-ntlm.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_error.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: test -f ntlm.log
# @TEST-EXEC: test ! -f tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f weird.log
