# @TEST-DOC: FreeTDS with login-only encryption: the TLS handshake inside PRELOGIN goes to the SSL analyzer, plaintext TDS resumes afterwards; ATTENTION, transactions, a named RPC with an output parameter.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-freetds.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f weird.log

