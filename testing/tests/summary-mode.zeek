# @TEST-DOC: TDS::message_log_mode = SUMMARY collapses tds.log to one line per connection per interval.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-workload.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds.log

redef TDS::message_log_mode = TDS::SUMMARY;
redef TDS::summary_interval = 10sec;
