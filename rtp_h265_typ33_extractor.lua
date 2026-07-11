--[[
Wireshark Lua plugin: extract an H.265 elementary stream from RTP
(payload type 33) into an Annex-B .265 file (playable in VLC/ffplay).

Tools -> Extract H265 from RTP. The current display filter is applied
on top of "rtp.p_type == 33".

Handles single NAL unit packets and fragmentation units (FU, type 49)
per RFC 7798. Aggregation packets (48) and PACI (50) are skipped.
Assumes a single RTP stream; interleaved SSRCs are not separated.
--]]

local rtp_payload_field = Field.new("rtp.payload")
local rtp_seq_field     = Field.new("rtp.seq")

-- H.265 NAL unit type: bits 1..6 of the first header byte
local function nal_type(b)
    return (b >> 1) & 0x3f
end

local function extract_h265_stream()
    local listener_filter = "rtp.p_type == 33"
    local user_filter = get_filter()
    if user_filter and user_filter ~= "" then
        listener_filter = listener_filter .. " and (" .. user_filter .. ")"
    end

    local log = TextWindow.new("H265 Stream Extractor")
    local function write_log(msg)
        log:append(os.date("%H:%M:%S ") .. msg .. "\n")
    end

    local out_path
    if get_preference then
        local dir = get_preference("gui.fileopen.dir")
        if dir and dir ~= "" then
            out_path = dir .. "/" .. os.date("h265_%Y%m%d_%H%M%S.265")
        end
    end
    out_path = out_path or ((os.getenv("HOME") or ".") .. "/" .. os.date("h265_%Y%m%d_%H%M%S.265"))

    local out = io.open(out_path, "wb")
    if not out then
        write_log("ERROR: failed to open '" .. out_path .. "'")
        return
    end

    -- collect payloads first, sort by sequence number, then reassemble
    local packets = {}
    local last_seq, seq_base

    local listener = Listener.new("ip", listener_filter)

    function listener.packet(pinfo, tvb)
        local seqs = { rtp_seq_field() }
        local payloads = { rtp_payload_field() }
        for i, payload in ipairs(payloads) do
            local seq_fi = seqs[i]
            if seq_fi and payload.value then
                local seq = seq_fi.value
                -- unwrap the 16-bit sequence number so sorting stays correct
                if last_seq == nil then
                    seq_base = 0
                elseif seq < 0x4000 and last_seq > 0xc000 then
                    seq_base = seq_base + 0x10000
                end
                last_seq = seq
                packets[#packets + 1] = { seq = seq_base + seq, payload = payload.value:raw() }
            end
        end
    end

    local function process_packets()
        table.sort(packets, function(a, b) return a.seq < b.seq end)

        local written, skipped = 0, 0
        local fu_header, fu_parts, fu_next_seq

        for _, pkt in ipairs(packets) do
            local p = pkt.payload
            if #p >= 2 then
                local b0, b1 = p:byte(1), p:byte(2)
                local t = nal_type(b0)

                if t == 49 then                     -- fragmentation unit
                    local fu = #p >= 4 and p:byte(3) or nil
                    if not fu then
                        skipped = skipped + 1
                    elseif (fu & 0x80) ~= 0 then    -- FU start: rebuild the real NAL header
                        fu_header = string.char((b0 & 0x81) | ((fu & 0x3f) << 1), b1)
                        fu_parts = { p:sub(4) }
                        fu_next_seq = pkt.seq + 1
                    elseif fu_parts and pkt.seq == fu_next_seq then
                        fu_parts[#fu_parts + 1] = p:sub(4)
                        fu_next_seq = pkt.seq + 1
                        if (fu & 0x40) ~= 0 then    -- FU end
                            out:write("\0\0\0\1", fu_header, table.concat(fu_parts))
                            written = written + 1
                            fu_parts = nil
                        end
                    else                            -- lost fragment, drop the partial NAL
                        fu_parts = nil
                        skipped = skipped + 1
                    end
                elseif t < 48 then                  -- single NAL unit packet
                    out:write("\0\0\0\1", p)
                    written = written + 1
                else                                -- 48 = AP, 50 = PACI
                    skipped = skipped + 1
                end
            end
        end

        return written, skipped
    end

    write_log("INFO: collecting RTP packets (filter: " .. listener_filter .. ")")
    retap_packets()
    listener:remove()

    local written, skipped = process_packets()
    out:close()

    write_log(string.format("INFO: %d packets, %d NAL units written", #packets, written))
    if skipped > 0 then
        write_log(string.format("WARN: %d packets skipped (unsupported type or lost fragment)", skipped))
    end
    write_log("INFO: stream saved to " .. out_path)
end

if gui_enabled() then
    register_menu("Extract H265 from RTP", extract_h265_stream, MENU_TOOLS_UNSORTED)
end
