# @TEST-DOC: INFO tokens are logged too when TDS::log_info_messages is set.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds_error.log

redef TDS::log_info_messages = T;
