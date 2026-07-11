--[[
Wireshark Lua plugin: JA4/JA4S TLS fingerprints over TCP and QUIC.

JA4 (client) comes from Wireshark's built-in tls.handshake.ja4 field
(4.2+; GREASE and the QUIC "q" prefix are handled there). JA4S (server)
is not provided by Wireshark, so it is computed here from the
ServerHello, following the FoxIO reference implementation:

    (t|q) version ext-count alpn _ cipher _ sha256(extensions)[1:12]

Tools -> Export JA4 Analysis writes all sessions to a CSV on the Desktop.
Requires Wireshark 4.4+ (Lua 5.4).

The JA4S spec is part of the JA4+ suite (https://github.com/FoxIO-LLC/ja4),
FoxIO License 1.1 — free for personal, academic and internal business use.
--]]

-- ==== SHA-256 (pure Lua 5.3+/5.4, native bitwise operators) ====

local SHA256_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

-- 32-bit rotate right (Lua integers are 64-bit, so mask after shifting)
local function rotr32(x, n)
    return ((x >> n) | (x << (32 - n))) & 0xffffffff
end

local function sha256_hex(msg)
    local h1, h2, h3, h4 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local h5, h6, h7, h8 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    local len = #msg
    msg = msg .. "\128" .. string.rep("\0", (-(len + 9)) % 64) .. string.pack(">I8", len * 8)

    for block = 1, #msg, 64 do
        local w = {}
        for j = 0, 15 do
            w[j + 1] = string.unpack(">I4", msg, block + j * 4)
        end
        for t = 17, 64 do
            local s0 = rotr32(w[t - 15], 7) ~ rotr32(w[t - 15], 18) ~ (w[t - 15] >> 3)
            local s1 = rotr32(w[t - 2], 17) ~ rotr32(w[t - 2], 19) ~ (w[t - 2] >> 10)
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xffffffff
        end

        local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
        for t = 1, 64 do
            local S1 = rotr32(e, 6) ~ rotr32(e, 11) ~ rotr32(e, 25)
            local ch = (e & f) ~ ((~e) & g)
            local temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) & 0xffffffff
            local S0 = rotr32(a, 2) ~ rotr32(a, 13) ~ rotr32(a, 22)
            local maj = (a & b) ~ (a & c) ~ (b & c)
            local temp2 = (S0 + maj) & 0xffffffff
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff
        end

        h1 = (h1 + a) & 0xffffffff
        h2 = (h2 + b) & 0xffffffff
        h3 = (h3 + c) & 0xffffffff
        h4 = (h4 + d) & 0xffffffff
        h5 = (h5 + e) & 0xffffffff
        h6 = (h6 + f) & 0xffffffff
        h7 = (h7 + g) & 0xffffffff
        h8 = (h8 + h) & 0xffffffff
    end

    return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h1, h2, h3, h4, h5, h6, h7, h8)
end

-- fail at load time instead of silently producing wrong fingerprints
assert(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
       "ja4_quic.lua: SHA-256 self-test failed")

-- ==== JA4S helpers ====

local TLS_VERSION_MAP = {
    [0x0304] = "13", [0x0303] = "12", [0x0302] = "11",
    [0x0301] = "10", [0x0300] = "s3", [0x0002] = "s2",
}

local GREASE = {
    [0x0a0a] = true, [0x1a1a] = true, [0x2a2a] = true, [0x3a3a] = true,
    [0x4a4a] = true, [0x5a5a] = true, [0x6a6a] = true, [0x7a7a] = true,
    [0x8a8a] = true, [0x9a9a] = true, [0xaaaa] = true, [0xbaba] = true,
    [0xcaca] = true, [0xdada] = true, [0xeaea] = true, [0xfafa] = true,
}

-- Build the JA4S fingerprint from ServerHello data: legacy version,
-- supported_versions extension values, chosen cipher, extension types
-- in order of appearance, chosen ALPN.
local function generate_ja4s(version, sup_versions, cipher, exts, alpn, is_quic)
    local ptype = is_quic and "q" or "t"

    -- The real negotiated version comes from the supported_versions
    -- extension (TLS 1.3); fall back to the legacy version field.
    local ver = nil
    for _, v in ipairs(sup_versions) do
        if not GREASE[v] and (ver == nil or v > ver) then ver = v end
    end
    ver = ver or version
    local ver_str = ver and TLS_VERSION_MAP[ver] or "00"

    local alpn_str = "00"
    if alpn and #alpn > 0 then
        alpn_str = alpn
        if #alpn_str > 2 then
            alpn_str = alpn_str:sub(1, 1) .. alpn_str:sub(-1)
        end
        if alpn_str:byte(1) > 127 then
            alpn_str = "99"
        end
    end

    local ext_strs = {}
    for i, e in ipairs(exts) do
        ext_strs[i] = string.format("%04x", e)
    end
    local ext_list = table.concat(ext_strs, ",")
    local ext_hash = (#ext_strs > 0) and sha256_hex(ext_list):sub(1, 12) or "000000000000"

    local prefix = string.format("%s%s%02d%s_%s",
        ptype, ver_str, math.min(#exts, 99), alpn_str,
        cipher and string.format("%04x", cipher) or "")
    return prefix .. "_" .. ext_hash, prefix .. "_" .. ext_list
end

-- ==== Wireshark fields ====

local function safe_tostring(val)
    if val == nil then return "" end
    return tostring(val)
end

-- Field.new() raises on unknown fields (older Wireshark), warn instead
local function try_field(name)
    local ok, f = pcall(Field.new, name)
    if ok then return f end
    print("ja4_quic.lua: field does not exist: " .. name)
end

local f_ja4          = try_field("tls.handshake.ja4")          -- built-in since Wireshark 4.2
local f_hs_type      = try_field("tls.handshake.type")
local f_hs_version   = try_field("tls.handshake.version")
local f_cipher       = try_field("tls.handshake.ciphersuite")
local f_ext_type     = try_field("tls.handshake.extension.type")
local f_sup_version  = try_field("tls.handshake.extensions.supported_version")
local f_alpn         = try_field("tls.handshake.extensions_alpn_str")
local f_sni          = try_field("tls.handshake.extensions_server_name")
local f_tcp_stream   = try_field("tcp.stream")
local f_udp_stream   = try_field("udp.stream")
local f_quic_conn    = try_field("quic.connection.number")

-- Return all values of a field occurring in the current packet, in order.
local function get_field_values(field)
    local values = {}
    if not field then return values end
    for _, fi in ipairs({ field() }) do
        if fi and fi.value ~= nil then
            table.insert(values, fi.value)
        end
    end
    return values
end

-- Return the value of the first occurrence of a field, or nil.
local function get_first_value(field)
    if not field then return nil end
    local fi = field()
    return fi and fi.value or nil
end

-- ==== Session tracking ====

local sessions = {}

-- Identify the connection this packet belongs to. QUIC connections are
-- tracked by quic.connection.number (survives connection migration),
-- everything else by tcp/udp stream index.
local function get_session_key()
    local qc = get_first_value(f_quic_conn)
    if qc ~= nil then return "quic:" .. safe_tostring(qc), true end
    local ts = get_first_value(f_tcp_stream)
    if ts ~= nil then return "tcp:" .. safe_tostring(ts), false end
    local us = get_first_value(f_udp_stream)
    if us ~= nil then return "udp:" .. safe_tostring(us), false end
    return nil, false
end

-- ==== GUI definitions ====

local ja4_field    = ProtoField.string("ja4_quic.ja4", "JA4 Fingerprint")
local ja4s_field   = ProtoField.string("ja4_quic.ja4s", "JA4S Fingerprint")
local ja4s_r_field = ProtoField.string("ja4_quic.ja4s_r", "JA4S Raw (unhashed)")
local sni_field    = ProtoField.string("ja4_quic.sni", "Server Name (SNI)")
local alpn_field   = ProtoField.string("ja4_quic.alpn", "ALPN Chosen")

local proto = Proto("ja4_quic", "JA4/JA4S Analysis (TCP & QUIC)")
proto.fields = { ja4_field, ja4s_field, ja4s_r_field, sni_field, alpn_field }

function proto.init()
    sessions = {}
end

function proto.dissector(buffer, pinfo, tree)
    local key, is_quic = get_session_key()
    if not key then return end

    local hs_types = get_field_values(f_hs_type)
    local session = sessions[key]

    if not session then
        -- start tracking a session once it shows a TLS handshake
        if #hs_types == 0 then return end
        session = {
            quic = is_quic,
            client_ip = safe_tostring(pinfo.src),
            server_ip = safe_tostring(pinfo.dst),
            start_time = pinfo.rel_ts,
            end_time = pinfo.rel_ts,
            upl_bytes = 0,
            down_bytes = 0,
        }
        sessions[key] = session
    end

    -- count each packet once: the postdissector runs again whenever
    -- the GUI re-dissects a packet (pinfo.visited)
    if not pinfo.visited then
        session.end_time = pinfo.rel_ts
        if safe_tostring(pinfo.src) == session.client_ip then
            session.upl_bytes = session.upl_bytes + pinfo.len
        else
            session.down_bytes = session.down_bytes + pinfo.len
        end
    end

    local seen_client_hello, seen_server_hello = false, false
    for _, t in ipairs(hs_types) do
        if t == 1 then seen_client_hello = true end
        if t == 2 then seen_server_hello = true end
    end

    -- ClientHello: take the JA4 computed by Wireshark itself plus the SNI.
    if seen_client_hello and not session.ja4 then
        session.ja4 = get_first_value(f_ja4)
        session.sni = get_first_value(f_sni)
        if session.ja4 then
            pinfo.cols.info:append(" [JA4: " .. session.ja4 .. "]")
        end
    end

    -- ServerHello: compute JA4S. In TLS 1.3 and QUIC the server ALPN lives
    -- in the encrypted EncryptedExtensions message, so without decryption
    -- keys it is simply absent here ("00"), same as other passive tools.
    if seen_server_hello and not session.ja4s then
        session.alpn = get_first_value(f_alpn)
        session.ja4s, session.ja4s_r = generate_ja4s(
            get_first_value(f_hs_version),
            get_field_values(f_sup_version),
            get_first_value(f_cipher),
            get_field_values(f_ext_type),
            session.alpn,
            session.quic)
        pinfo.cols.info:append(" [JA4S: " .. session.ja4s .. "]")
    end

    -- Show what we know about this session on every one of its packets.
    if session.ja4 or session.ja4s then
        local subtree = tree:add(proto, "JA4/JA4S Analysis" .. (session.quic and " [QUIC]" or " [TCP]"))
        if session.ja4 then subtree:add(ja4_field, session.ja4):set_generated(true) end
        if session.ja4s then
            subtree:add(ja4s_field, session.ja4s):set_generated(true)
            subtree:add(ja4s_r_field, session.ja4s_r):set_generated(true)
        end
        if session.sni then subtree:add(sni_field, session.sni):set_generated(true) end
        if session.alpn then subtree:add(alpn_field, session.alpn):set_generated(true) end
    end
end

register_postdissector(proto)

-- ==== CSV Export via Tools Menu ====
if gui_enabled() then
    register_menu("Tools/Export JA4 Analysis", function()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE")
        local path = home .. "/Desktop/ja4_fingerprints.csv"

        local outfile = io.open(path, "w")
        if not outfile then
            local tw = TextWindow.new("JA4 Export Error")
            tw:append("Could not open file for writing: " .. path .. "\n")
            return
        end

        outfile:write("session,transport,client_ip,server_ip,sni,alpn,ja4,ja4s,ja4s_raw,upl_bytes,down_bytes,duration\n")
        for key, s in pairs(sessions) do
            outfile:write(string.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%.2f\n",
                key,
                s.quic and "quic" or "tcp",
                s.client_ip or "",
                s.server_ip or "",
                s.sni or "",
                s.alpn or "",
                s.ja4 or "",
                s.ja4s or "",
                s.ja4s_r or "",
                s.upl_bytes, s.down_bytes,
                s.end_time - s.start_time))
        end
        outfile:close()

        local tw = TextWindow.new("JA4 Export Info")
        tw:append("Saved JA4/JA4S analysis to: " .. path .. "\n")
    end, MENU_TOOLS_UNSORTED)
end
