# @TEST-DOC: A failed login counts toward Login_Bruteforce; with the threshold at one it fires on the failed-login trace.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-failed-login.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut note msg < notice.log > notices
# @TEST-EXEC: btest-diff notices

redef TDS::bruteforce_threshold = 1.0;
