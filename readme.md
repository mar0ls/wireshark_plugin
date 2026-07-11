<p align="center">
  <img src="https://github.com/user-attachments/assets/4893c298-dd62-4d8e-90e0-b4ccf77d74ce" width="25%">
</p>

# Wireshark Lua Plugins

Lua plugins extending Wireshark's packet analysis. Requires Wireshark 4.4+.

## Plugins

### ja4_quic.lua
JA4 (client) and JA4S (server) TLS fingerprints for sessions over **TCP and QUIC/HTTP3**.
JA4 is read from Wireshark's built-in `tls.handshake.ja4` field; JA4S is computed from the
ServerHello, following the [FoxIO reference implementation](https://github.com/FoxIO-LLC/ja4).

- filterable fields: `ja4_quic.ja4`, `ja4_quic.ja4s`, `ja4_quic.ja4s_r`, `ja4_quic.sni`, `ja4_quic.alpn`
- Tools → Export JA4 Analysis writes all sessions to `~/Desktop/ja4_fingerprints.csv`
- note: JA4S is part of the JA4+ suite (FoxIO License 1.1 — free for personal, academic and internal business use)

### ja3_tls.lua
JA3/JA3S session analysis for TLS over TCP, based on Wireshark's built-in
`tls.handshake.ja3*` fields. Tracks per-stream traffic stats and flags simple
anomalies (possible exfiltration / bulk download).

- filterable fields: `tls_ja3.fingerprint`, `tls_ja3.ja3s_fingerprint`, `tls_ja3.anomaly`
- Tools → Export JA3 Analysis writes all sessions to `~/Desktop/tls_fingerprints.csv`

### check_asn.lua
Offline ASN lookup: adds source/destination ASN and organization to every packet
(`asn_info.*` fields). Uses the [iptoasn.com](https://iptoasn.com) IPv4 database —
download [ip2asn-v4.tsv.gz](https://iptoasn.com/data/ip2asn-v4.tsv.gz), extract it
and set `ASN_DB_PATH` at the top of the script.

### check_ipinfo.lua
Tools → Check IPinfo: prompts for an IP address and opens its
[ipinfo.io](https://ipinfo.io) page in the default browser.

### rtp_h265_typ33_extractor.lua
Tools → Extract H265 from RTP: extracts an H.265 elementary stream from RTP
(payload type 33) into an Annex-B `.265` file, playable in VLC/ffplay.
Handles single NAL unit packets and FU fragmentation (RFC 7798); aggregation
packets (AP) and PACI are skipped. The current display filter is respected.

## Installation

Copy the scripts into your personal Lua plugins directory
(check `About Wireshark → Folders → Personal Lua Plugins`):

- macOS/Linux: `~/.local/lib/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

Reload without restarting: **Analyze → Reload Lua Plugins** (Ctrl/Cmd+Shift+L).

## Contributing

PRs welcome — fork, branch, commit with a clear description.
