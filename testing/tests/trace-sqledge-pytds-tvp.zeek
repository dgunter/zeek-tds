# @TEST-DOC: A stored procedure called with a table-valued parameter: the TVP's type name and row count are rendered, the rows are parsed with the table type's column metadata.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sqledge-pytds-tvp.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff tds_rpc.log
# @TEST-EXEC: btest-diff tds_sql_batch.log
# @TEST-EXEC: test ! -f weird.log
