# @TEST-DOC: pytds with full encryption: the TLS handshake travels inside PRELOGIN packets and everything after it is bare TLS records on the stream. Both reach the SSL analyzer; tds_login.log marks the session encrypted and the TDS logs stop at the PRELOGIN exchange.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-tls.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: test ! -f tds_sql_batch.log
# @TEST-EXEC: test ! -f tds_rpc.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f weird.log
