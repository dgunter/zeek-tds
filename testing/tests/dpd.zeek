# @TEST-DOC: The analyzer is also enabled by signature, without a registered port.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-setup.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds_login.log

redef TDS::ports = {};
