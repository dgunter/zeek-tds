# @TEST-DOC: Microsoft.Data.SqlClient without MARS, login-only encryption, column encryption feature negotiated (CEK table in COLMETADATA).
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-dotnet-plain.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f weird.log
