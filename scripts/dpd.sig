# TDS PRELOGIN request: packet type 0x12, EOM status, then the option table starting
# with VERSION (token 0x00, 6 bytes) followed by ENCRYPTION (token 0x01, 1 byte).
signature dpd_tds_prelogin {
    ip-proto == tcp
    payload /^\x12\x01[\x00-\x10].\x00\x00[\x00\x01]\x00\x00\x00.\x00\x06\x01\x00.\x00\x01/
    enable "TDS"
}

# TDS7 LOGIN7 request sent without a PRELOGIN (older clients): type 0x10, then a
# little-endian length and a 7.x TDS version.
signature dpd_tds_login7 {
    ip-proto == tcp
    payload /^\x10\x01.{6}.{3}\x00.{2}[\x00-\x0b][\x70-\x74]/
    enable "TDS"
}
