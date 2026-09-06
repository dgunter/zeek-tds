# @TEST-DOC: SQL Server Browser (SSRP, UDP 1434): enumeration, per-instance lookups and a DAC port request, each answered, in ssrp.log.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/ssrp-browser.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff ssrp.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: test ! -f weird.log
