--[[  
 * Add this file to the appropriate Wireshark plugin directory:  
 *  
 * macOS: /Applications/Wireshark.app/Contents/PlugIns/wireshark/  
 * Windows: C:\Program Files\Wireshark\Plugins\  
 * Linux: /usr/lib/wireshark/plugins/ (for system-wide plugins)  
 *  
 * After adding the script, you can :   
 * - Go to **Analyze -> Reload Lua Plugins** to apply changes without restarting  
 *  
 * Once loaded, the script will add a new option under:  
 * **Tools -> Extract H265 stream from RTP**  
]]


-- Set the jitter buffer limit (configurable)
local JITTER_BUFFER_LIMIT = 50  

-- Define RTP payload and sequence number fields
local rtp_data_field = Field.new("rtp.payload")  -- RTP payload field
local rtp_sequence_field = Field.new("rtp.seq")  -- RTP sequence number field

-- Write buffer size (1 MB) to improve efficiency
local WRITE_BUFFER_SIZE = 1024 * 1024  -- Buffer size for writing data

local function extract_h265_stream()
    -- Function to create packet filter for RTP packets
    local function create_packet_filter(custom_filter)
        local base_filter = "rtp"
        return custom_filter and custom_filter ~= "" and (base_filter .. " and (" .. custom_filter .. ")") or base_filter
    end

    -- Create a packet listener for RTP packets
    local packet_listener = Listener.new("ip", create_packet_filter(get_filter()))
    local log_window = TextWindow.new("H265 Stream Extractor")
    local output_file_path = ""  -- Path to the output file
    local packet_buffer = {}  -- Buffer for storing RTP packets
    local processing_round = 0  -- Processing stage tracker
    local total_packets = 0  -- Total number of packets processed
    local initial_packet_count = 0  -- Counter for initial packet count
    local last_sequence = 0  -- Last sequence number received
    local file_handle = nil  -- File handle for writing output
    local write_buffer = ""  -- Buffer for writing data before saving to file
    local fu_buffer = {}  -- Buffer for FU-A fragments

    -- Function to log messages to the UI window
    local function write_log(message)
        log_window:append(os.date("%H:%M:%S ") .. message .. "\n")
    end

    -- Initialize output file for writing H.265 data
    local function init_output_file()
        if get_preference then
            local save_dir = get_preference("gui.fileopen.dir")
            if not save_dir or save_dir == "" then
                write_log("ERROR: Save directory not set.")
                return false
            end
            output_file_path = save_dir .. "/" .. os.date("h265_%Y%m%d_%H%M%S.265")
        else
            output_file_path = "output.265"
        end
        file_handle = io.open(output_file_path, "wb")
        if not file_handle then
            write_log("ERROR: Failed to open '" .. output_file_path .. "'")
            return false
        end
        write_log("INFO: Saving stream to " .. output_file_path)
        return true
    end

    -- Flush data buffer to file
    local function flush_write_buffer()
        if file_handle and #write_buffer > 0 then
            file_handle:write(write_buffer)
            write_buffer = ""
        end
    end

    -- Buffer and write NAL unit to file
    local function buffer_nal_unit(h265_data)
        write_buffer = write_buffer .. "\00\00\00\01" .. h265_data:tvb()():raw()
        if #write_buffer >= WRITE_BUFFER_SIZE then
            flush_write_buffer()
        end
    end

    -- Improved sequence comparison function to avoid sorting errors
    local function compare_sequences(seq_a, seq_b)
        if not seq_a or not seq_b or not seq_a.key or not seq_b.key then
            return false
        end
        return ((seq_a.key - seq_b.key) % 65536) < 32768
    end

    -- Process RTP packet in the correct order
    local function process_ordered_packet(sequence, payload_data)
        if not payload_data or payload_data:len() < 2 then
            write_log("WARN: Ignoring small RTP packet")
            return
        end

        local nal_header = payload_data:get_index(0)
        local nal_unit_type = bit.band(nal_header, 0x1f)

        if nal_unit_type > 0 and nal_unit_type < 24 then
            -- Single NAL unit
            buffer_nal_unit(payload_data)
        elseif nal_unit_type == 49 then  -- FU-A (Fragmentation Unit)
            local fu_header = payload_data:get_index(1)
            local fu_type = bit.band(fu_header, 0x1f)
            local fu_start = bit.band(fu_header, 0x80) ~= 0
            local fu_end = bit.band(fu_header, 0x40) ~= 0

            if fu_start then
                fu_buffer = { [sequence] = payload_data:range(2):tvb()():raw() }
            elseif fu_buffer[last_sequence] then
                fu_buffer[sequence] = payload_data:range(2):tvb()():raw()
                if fu_end then
                    local complete_nal = "\00" .. string.char(bit.bor(bit.band(nal_header, 0xe0), fu_type)) .. table.concat(fu_buffer)
                    buffer_nal_unit(ByteArray.new(complete_nal):tvb("FU-A"))
                    fu_buffer = {}
                end
            end
        else
            write_log("WARN: Unsupported NAL type: " .. nal_unit_type)
        end
    end

    -- Handle incoming RTP packet
    local function handle_rtp_packet(sequence, payload)
        local current_seq = sequence.value
        for _, pkt in ipairs(packet_buffer) do
            if pkt.key == current_seq then return end
        end
        if total_packets == 0 then
            last_sequence = current_seq
        elseif current_seq == last_sequence then
            return
        else
            last_sequence = current_seq
        end

        total_packets = total_packets + 1
        table.insert(packet_buffer, { key = tonumber(sequence.value), value = payload.value })

        if #packet_buffer < 2 then
            write_log("WARN: Not enough packets to sort, skipping")
            return
        end

        table.sort(packet_buffer, compare_sequences)
        process_ordered_packet(packet_buffer[1].key, packet_buffer[1].value)
        table.remove(packet_buffer, 1)
    end

    function packet_listener.packet(pinfo, tvb)
        local payloads = { rtp_data_field() }
        local sequences = { rtp_sequence_field() }

        if not payloads[1] or not sequences[1] then
            write_log("ERROR: Missing RTP payload or sequence number")
            return
        end

        for i, payload in ipairs(payloads) do
            handle_rtp_packet(sequences[1], payload)
        end
    end

    function packet_listener.reset() end
    function packet_listener.draw() end

    -- Cleanup function to flush buffer and close file
    local function cleanup()
        flush_write_buffer()
        if file_handle then
            file_handle:close()
            file_handle = nil
            write_log("INFO: Stream saved to " .. output_file_path)
        end
        packet_listener:remove()
    end

    if not init_output_file() then return end
    write_log("INFO: Starting extraction")
    log_window:set_atclose(cleanup)

    processing_round = 0
    retap_packets()

    processing_round = 1
    retap_packets()

    write_log("INFO: Extraction completed")
    write_log("INFO: File successfully saved at: " .. output_file_path)
end

-- Register menu option in Wireshark
register_menu("Extract H265 from RTP", extract_h265_stream, MENU_TOOLS_UNSORTED)

