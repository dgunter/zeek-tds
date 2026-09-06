# @TEST-DOC: SQL Browser enumeration counts toward TDS::Scan; with the threshold at one server it fires on the SSRP trace.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/ssrp-browser.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut note msg < notice.log > notices
# @TEST-EXEC: btest-diff notices

redef TDS::scan_threshold = 1.0;
