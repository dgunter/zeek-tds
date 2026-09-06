# @TEST-DOC: tds_result.log is opt-in: one line per result set with columns, types and row count, plus the first rows when TDS::result_sample_rows is set.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds_result.log
# @TEST-EXEC: btest-diff tds_rpc.log

redef TDS::log_results = T;
redef TDS::result_sample_rows = 3;
