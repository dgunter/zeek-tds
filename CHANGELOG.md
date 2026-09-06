# Changelog

## Unreleased

- Spicy-level tests: a harness module exposes the grammar's units to
  spicy-driver for byte-level unit tests, and a batch-mode test replays both
  directions of a trace through the shared connection context without Zeek.
- Formatting enforced with spicy-format and zeek-format; grammar and scripts
  reformatted.
- CI produces SonarCloud generic reports (btest results, Zeek script coverage
  from the script profiler, formatter findings) and scans when a token is set.

## 0.2.0 - 2026-09-06

- MARS: TDS packets wrapped in SMP session multiplexing are unwrapped and
  messages are reassembled per session; tds.log gains a `session` column.
- Always Encrypted: the COLUMNENCRYPTION feature acknowledgement is tracked
  and COLMETADATA's key table and per-column crypto metadata are parsed.
- Per-log switches, and a `TDS::message_log_mode` of PER_MESSAGE, SUMMARY
  (one line per connection per interval) or DISABLED for tds.log.
- Corpus: Microsoft.Data.SqlClient captures with and without MARS.
- Integrated authentication: NTLM and GSS-API tokens in LOGIN7, SSPI messages
  and SSPI response tokens are forwarded to Zeek's NTLM and GSSAPI analyzers;
  tds_login.log gains `sspi_mechanism`.
- tds_login.log: `password_in_clear`, LOGIN7 feature extensions (`features`,
  `user_agent`, `fedauth_library`) and ENVCHANGE routing (`routed_to`).
- tds_rpc.log lines are written when the response arrives and carry the
  output parameter values (`output`) and `return_status`.
- detect.zeek: notices for login brute force, dangerous statements and
  procedures, PRELOGIN scanning, large results, bulk loads, cleartext
  passwords and first-seen applications; docs/attack-coverage.md maps logs and
  notices to ATT&CK and ICS ATT&CK techniques.
- Table-valued parameters (type name and row count, rows parsed with the
  table type's columns) and Always Encrypted parameter cipher metadata in RPCs.
- Bulk loads are parsed as token streams; tds.log counts their rows.
- SSRP (SQL Server Browser, UDP 1434) analyzer and ssrp.log: enumeration,
  instance lookups and DAC port requests with the server's inventory answer;
  enumeration counts toward TDS::Scan.
- New opt-in tds_result.log: columns, types and row count per result set, with
  optional rendered sample rows (`TDS::log_results`, `TDS::result_sample_rows`).

## 0.1.0 - 2026-09-05

First release. Spicy analyzer for TDS 7.x with tds, tds_login, tds_sql_batch,
tds_rpc and tds_error logs, typed RPC parameter decoding including numbered
procedures, server token stream parsing, TLS hand-off to the SSL analyzer, and a
btest suite over Azure SQL Edge and historical captures.
