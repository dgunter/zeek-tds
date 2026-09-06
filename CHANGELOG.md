# Changelog

## Unreleased

- MARS: TDS packets wrapped in SMP session multiplexing are unwrapped and
  messages are reassembled per session; tds.log gains a `session` column.
- Always Encrypted: the COLUMNENCRYPTION feature acknowledgement is tracked
  and COLMETADATA's key table and per-column crypto metadata are parsed.
- Per-log switches, and a `TDS::message_log_mode` of PER_MESSAGE, SUMMARY
  (one line per connection per interval) or DISABLED for tds.log.
- Corpus: Microsoft.Data.SqlClient captures with and without MARS.

## 0.1.0 - 2026-09-05

First release. Spicy analyzer for TDS 7.x with tds, tds_login, tds_sql_batch,
tds_rpc and tds_error logs, typed RPC parameter decoding including numbered
procedures, server token stream parsing, TLS hand-off to the SSL analyzer, and a
btest suite over Azure SQL Edge and historical captures.
