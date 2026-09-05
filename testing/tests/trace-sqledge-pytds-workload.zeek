# @TEST-DOC: pytds session with sp_executesql inserts of every common data type, a 60-row result with NULLs (NBCROW), a stored procedure with an output parameter, transactions, ERROR and INFO tokens and PLP chunks.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log
# @TEST-EXEC: btest-diff tds_login.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: btest-diff tds_error.log
# @TEST-EXEC: test ! -f ssl.log
# @TEST-EXEC: test ! -f weird.log

