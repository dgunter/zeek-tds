# @TEST-DOC: Microsoft.Data.SqlClient with MARS: TDS packets wrapped in SMP session multiplexing, two result sets interleaved on sessions 1 and 2, a procedure with output and return parameters, a transaction.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-dotnet-mars.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: test ! -f tds_error.log
# @TEST-EXEC: test ! -f weird.log
