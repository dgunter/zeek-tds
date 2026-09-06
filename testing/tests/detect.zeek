# @TEST-DOC: Detections: a dangerous pattern in a batch and in an sp_executesql parameter, a large result, a bulk load, cleartext password, and new application, with thresholds lowered to fire on the corpus.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut note msg sub < notice.log > notices
# @TEST-EXEC: btest-diff notices

redef TDS::dangerous_patterns += /raiserror/ | /count\(\*\) from dbo\.readings/;
redef TDS::large_result_rows = 50;
redef TDS::detect_cleartext_password = T;
redef TDS::detect_new_applications = T;
