# ATT&CK coverage

What the logs and notices give you for each technique. "Evidence" is where the
raw fact lands; "Notice" is the built-in detection in `detect.zeek`, if any.
Everything else is a SIEM query away, since every line carries the connection
`uid` and joins to `conn.log`, `ssl.log` and `ntlm.log`.

## Enterprise ATT&CK

| Technique | Evidence | Notice |
| --- | --- | --- |
| T1046 Network Service Discovery | `tds_login.log` lines with PRELOGIN fields but no LOGIN7 and no login result (probes); `conn.log` for connections that never send PRELOGIN | `TDS::Scan` |
| T1110 Brute Force (.001 guessing, .003 spraying) | `tds_error.log` 18456, `tds_login.log` `success F` with `username` and `hostname`; state 1 means the server hid the reason | `TDS::Login_Bruteforce` |
| T1078 Valid Accounts, T1078.001 Default Accounts | `tds_login.log`: `username`, `hostname`, `app_name`, `library`, `client_mac`; `sa` from a workstation | `TDS::New_Application` |
| T1552 / T1557 Unsecured Credentials, adversary-in-the-middle | `tds_login.log` `password_in_clear`, `encrypted F`, `client_encryption` / `server_encryption` | `TDS::Cleartext_Password` |
| T1550.002 Pass the Hash, T1558 Kerberos tickets | integrated logins are handed to Zeek's NTLM and GSSAPI analyzers: `ntlm.log`, `kerberos.log` under the same `uid`; `tds_login.log` `sspi_mechanism` | |
| T1059.003 Command Shell via SQL Server (`xp_cmdshell`), T1059 with OLE automation (`sp_OACreate`) | `tds_sql_batch.log` `query`, `tds_rpc.log` `procedure`, `parameters`, `statement` | `TDS::Dangerous_Statement` |
| T1505.001 Server Software Component: SQL Stored Procedures (startup procedures, triggers, CLR assemblies) | `CREATE ASSEMBLY`, `sp_procoption`, `CREATE TRIGGER` in `tds_sql_batch.log`; `tds_rpc.log` | `TDS::Dangerous_Statement` |
| T1136 Create Account, T1098 Account Manipulation | `CREATE LOGIN`, `sp_addlogin`, `ALTER LOGIN`, `sp_password`, `sp_addsrvrolemember`, `ALTER SERVER ROLE ... ADD MEMBER` in the batch and RPC logs | `TDS::Dangerous_Statement` |
| T1012 Query Registry, T1112 Modify Registry | `xp_regread`, `xp_regwrite` and friends | `TDS::Dangerous_Statement` |
| T1083 File and Directory Discovery | `xp_dirtree`, `xp_fileexist`, `xp_subdirs` | `TDS::Dangerous_Statement` |
| T1187 Forced Authentication (NTLM relay via UNC path) | `xp_dirtree`, `xp_fileexist`, `BACKUP ... TO DISK = '\\...'` with a UNC path; the outbound SMB then appears in `smb_files.log` from the server | `TDS::Dangerous_Statement` |
| T1021 / T1210 Lateral movement over linked servers | `sp_addlinkedserver`, `OPENROWSET`, `OPENDATASOURCE`, `EXEC ... AT server`; the second-hop TDS session from the server | `TDS::Dangerous_Statement` |
| T1003 / T1555 Credential access from the database | `sys.sql_logins`, `password_hash`, `sys.syslogins` | `TDS::Dangerous_Statement` |
| T1053 Scheduled Task (SQL Agent jobs) | `sp_add_job`, `sp_add_jobstep`, `sp_start_job` | `TDS::Dangerous_Statement` |
| T1190 Exploit Public-Facing Application (SQL injection) | `WAITFOR DELAY`, stacked statements in `tds_sql_batch.log`; syntax errors 102 and 105 and object errors 208 in `tds_error.log` following user-facing hosts | `TDS::Dangerous_Statement` for the timing probes |
| T1213 Data from Information Repositories, T1005 Data from Local System | `tds_result.log` columns and row counts (opt-in); `tds.log` `rows` and `len`; `OPENROWSET(BULK ...)` reading files | `TDS::Large_Result` |
| T1030 Data Transfer Size Limits, T1041 Exfiltration over C2 channel | `tds.log` `rows`, `len`, `packets` per response; summary mode totals | `TDS::Large_Result` |
| T1105 Ingress Tool Transfer, T1074 Data Staged | `tds.log` `bulk_load`, `INSERT BULK` in `tds_sql_batch.log` | `TDS::Bulk_Load` |
| T1485 Data Destruction, T1565.001 Stored Data Manipulation | `DROP`, `TRUNCATE`, `DELETE`, `UPDATE` against sensitive tables in `tds_sql_batch.log` and `tds_rpc.log`, with `transaction_descriptor` to reassemble the transaction | |
| T1070 Indicator Removal | `sp_cycle_errorlog`, `DBCC` log manipulation, `ALTER DATABASE ... SET RECOVERY SIMPLE` in the batch log | |
| T1562 Impair Defenses | `sp_configure` disabling auditing or enabling features, `ALTER SERVER AUDIT ... STATE = OFF` | `TDS::Dangerous_Statement` for the configure cases |

## ICS ATT&CK

Historians, MES and alarm databases are almost always SQL Server.

| Technique | Evidence | Notice |
| --- | --- | --- |
| T0846 Remote System Discovery, T0888 Remote System Information Discovery | PRELOGIN probes; `server_version`, `server_product_version` in `tds_login.log` tell an attacker (and you) the exact build | `TDS::Scan` |
| T0812 Default Credentials, T0859 Valid Accounts | `tds_login.log` `username sa`, `has_password`, `success` | `TDS::Login_Bruteforce`, `TDS::New_Application` |
| T0886 Remote Services | every TDS session: who talks to the historian, with which client | |
| T0811 Data from Information Repositories, T0882 Theft of Operational Information | `tds_result.log`, `tds.log` `rows`; statements against tag and event tables in `tds_sql_batch.log` and `tds_rpc.log` | `TDS::Large_Result` |
| T0832 Manipulation of View, T0836 Modify Parameter, T0831 Manipulation of Control (when setpoints or recipes live in the database) | `UPDATE` and `INSERT` on configuration tables with `transaction_descriptor`; `sp_executesql` statements and parameter values in `tds_rpc.log` | |
| T0809 Data Destruction | `DROP`, `TRUNCATE`, `DELETE` | |
| T0853 Scripting, T0807 Command-Line Interface | `xp_cmdshell`, `sp_OACreate` from an engineering workstation | `TDS::Dangerous_Statement` |
| T0865 Spearphishing Attachment -> T0843 Program Download chains that land on the historian | `BULK INSERT`, `OPENROWSET(BULK ...)`, CLR assemblies | `TDS::Dangerous_Statement`, `TDS::Bulk_Load` |

## Limits

- Encrypted sessions (`encrypted T` with `client_encryption on`) expose only the
  login negotiation and the TLS certificate; everything else above needs
  plaintext or login-only encryption, which is still the norm on ICS networks.
- Result contents are opt-in (`TDS::log_results`, `TDS::result_sample_rows`).
- The dangerous-statement patterns are string matches on decoded text; obfuscated
  SQL (`EXEC(CHAR(...)+...)`, `sp_executesql` with concatenated fragments) can
  evade them. The logs still have the text for a smarter matcher downstream.
