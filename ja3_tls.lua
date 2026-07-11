--[[
Wireshark Lua plugin: JA3/JA3S TLS session analysis.

Uses the JA3/JA3S values computed by Wireshark itself
(tls.handshake.ja3* fields, built in since 4.2), so GREASE values are
handled per the JA3 spec. Tracks per-stream traffic stats, flags simple
anomalies and exports sessions to CSV via Tools -> Export JA3 Analysis.

TCP only; for QUIC/HTTP3 see ja4_quic.lua.
--]]

local function try_field(name)
    local ok, f = pcall(Field.new, name)
    if ok then return f end
    print("ja3_tls.lua: field does not exist: " .. name)
end

local f_hs_type   = try_field("tls.handshake.type")
local f_ja3       = try_field("tls.handshake.ja3")
local f_ja3_full  = try_field("tls.handshake.ja3_full")
local f_ja3s      = try_field("tls.handshake.ja3s")
local f_ja3s_full = try_field("tls.handshake.ja3s_full")
local f_stream    = try_field("tcp.stream")

local function first_value(field)
    if not field then return nil end
    local fi = field()
    return fi and fi.value or nil
end

local sessions = {}

local function classify_anomaly(s)
    if s.upl_bytes > 50000 and s.down_bytes < 5000 then
        return "Possible data exfiltration"
    elseif s.down_bytes > 100000 and s.upl_bytes < 1000 then
        return "Possible data download"
    elseif s.upl_bytes > 10000 and s.down_bytes > 10000
            and (s.end_time - s.start_time) < 1 then
        return "High volume short session"
    end
end

local ja3_field     = ProtoField.string("tls_ja3.fingerprint", "JA3 Fingerprint")
local ja3s_field    = ProtoField.string("tls_ja3.ja3s_fingerprint", "JA3S Fingerprint")
local anomaly_field = ProtoField.string("tls_ja3.anomaly", "Traffic Anomaly")

local proto = Proto("tls_ja3", "TLS JA3/JA3S Analysis")
proto.fields = { ja3_field, ja3s_field, anomaly_field }

function proto.init()
    sessions = {}
end

function proto.dissector(buffer, pinfo, tree)
    local stream = first_value(f_stream)
    if stream == nil then return end
    local key = tostring(stream)

    local session = sessions[key]
    if not session then
        -- start tracking a stream once it shows a TLS handshake
        if not (f_hs_type and f_hs_type()) then return end
        session = {
            client_ip = tostring(pinfo.src),
            server_ip = tostring(pinfo.dst),
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
        if tostring(pinfo.src) == session.client_ip then
            session.upl_bytes = session.upl_bytes + pinfo.len
        else
            session.down_bytes = session.down_bytes + pinfo.len
        end
    end

    if not session.ja3_hash then
        session.ja3_hash = first_value(f_ja3)
        session.ja3 = first_value(f_ja3_full)
        if session.ja3_hash then
            pinfo.cols.info:append(" [JA3: " .. session.ja3_hash .. "]")
        end
    end
    if not session.ja3s_hash then
        session.ja3s_hash = first_value(f_ja3s)
        session.ja3s = first_value(f_ja3s_full)
        if session.ja3s_hash then
            pinfo.cols.info:append(" [JA3S: " .. session.ja3s_hash .. "]")
        end
    end

    if not (session.ja3_hash or session.ja3s_hash) then return end

    local subtree = tree:add(proto, "TLS JA3/JA3S Analysis")
    if session.ja3_hash then
        subtree:add(ja3_field, session.ja3_hash)
               :append_text(" (" .. (session.ja3 or "") .. ")")
    end
    if session.ja3s_hash then
        subtree:add(ja3s_field, session.ja3s_hash)
               :append_text(" (" .. (session.ja3s or "") .. ")")
    end
    local anomaly = classify_anomaly(session)
    if anomaly then
        subtree:add(anomaly_field, anomaly):set_generated(true)
    end
end

register_postdissector(proto)

if gui_enabled() then
    register_menu("Tools/Export JA3 Analysis", function()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE")
        local path = home .. "/Desktop/tls_fingerprints.csv"

        local out = io.open(path, "w")
        if not out then
            TextWindow.new("JA3 Export Error"):append("Could not open " .. path .. "\n")
            return
        end

        out:write("stream,client_ip,server_ip,ja3,ja3_hash,ja3s,ja3s_hash,upl_bytes,down_bytes,duration,anomaly\n")
        for id, s in pairs(sessions) do
            out:write(string.format("%s,%s,%s,%s,%s,%s,%s,%d,%d,%.2f,%s\n",
                id,
                s.client_ip or "",
                s.server_ip or "",
                s.ja3 or "",
                s.ja3_hash or "",
                s.ja3s or "",
                s.ja3s_hash or "",
                s.upl_bytes, s.down_bytes,
                s.end_time - s.start_time,
                classify_anomaly(s) or ""))
        end
        out:close()

        TextWindow.new("JA3 Export Info"):append("Saved JA3 analysis to: " .. path .. "\n")
    end, MENU_TOOLS_UNSORTED)
end
