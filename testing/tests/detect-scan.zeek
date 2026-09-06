# @TEST-DOC: A PRELOGIN-only connection counts as a probe; with the threshold at one server the TLS trace, whose login is invisible, does not (encrypted), but a bare PRELOGIN does.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-tls.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test ! -f notice.log

redef TDS::scan_threshold = 1.0;
