--[[  
 * Add this file to the appropriate Wireshark plugin directory:  
 *  
 * macOS: /Applications/Wireshark.app/Contents/PlugIns/wireshark/  
 * Windows: C:\Program Files\Wireshark\Plugins\  
 * Linux: /usr/lib/wireshark/plugins/ (for system-wide plugins)  
 *  
 * After adding the script, no manual intervention needed; the script runs this function automatically  
]]

-- Define a new Wireshark dissector for ASN information
local asn_proto = Proto("ASN_Info", "ASN Information") 

-- Define ASN and organization fields for Wireshark display
src_asn_field = ProtoField.string("asn_info.src", "Source ASN")
src_org_field = ProtoField.string("asn_info.src_org", "Source Organization")
dst_asn_field = ProtoField.string("asn_info.dst", "Destination ASN")
dst_org_field = ProtoField.string("asn_info.dst_org", "Destination Organization")

asn_proto.fields = { src_asn_field, src_org_field, dst_asn_field, dst_org_field }

-- Table to store IP-to-ASN mappings
local asn_db = {}

-- Converts an IPv4 address string into a numeric representation for easier range comparison
local function ip_to_number(ip)
    local o1, o2, o3, o4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not o1 then return nil end
    return (tonumber(o1) * 256^3) + (tonumber(o2) * 256^2) + (tonumber(o3) * 256) + tonumber(o4)
end

-- Checks if an IP address belongs to a private (RFC 1918) range
local function is_private_ip(ip)
    local ip_num = ip_to_number(ip)
    if not ip_num then return false end

    -- Private IPv4 ranges according to RFC 1918
    local private_ranges = {
        {ip_to_number("10.0.0.0"), ip_to_number("10.255.255.255")},
        {ip_to_number("172.16.0.0"), ip_to_number("172.31.255.255")},
        {ip_to_number("192.168.0.0"), ip_to_number("192.168.255.255")}
    }

    for _, range in ipairs(private_ranges) do
        if ip_num >= range[1] and ip_num <= range[2] then
            return true
        end
    end

    return false
end

-- Loads an ASN database from a TSV file (tab-separated values)
function load_asn_database(filename)
    local file = io.open(filename, "r")
    if not file then
        print("Error: ASN file not found: " .. filename)
        return
    end

    for line in file:lines() do
        line = line:gsub("\r", "")  -- Remove carriage return for Windows compatibility

        -- Parse all columns from the TSV file
        local ip_start, ip_end, asn, country, org = line:match("([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t(.+)")

        if ip_start and ip_end and asn and org then
            local ip_start_num = ip_to_number(ip_start)
            local ip_end_num = ip_to_number(ip_end)

            if ip_start_num and ip_end_num then
                table.insert(asn_db, {
                    ip_start = ip_start_num,
                    ip_end = ip_end_num,
                    asn = "AS" .. asn,
                    org = org
                })
            end
        else
            print(" Invalid line in ASN file: " .. line)
        end
    end

    file:close()
    print(" Loaded " .. tostring(#asn_db) .. " ASN entries")

    -- Sort the database for efficient binary search
    table.sort(asn_db, function(a, b) return a.ip_start < b.ip_start end)
end

-- Retrieves ASN and organization information for a given IP
function get_asn_info(ip)
    if is_private_ip(ip) then
        return "Private IP", "Local Network"
    end

    local ip_num = ip_to_number(ip)
    if not ip_num then return "No ASN", "Unknown Organization" end

    -- Perform binary search for efficient lookup
    local left, right = 1, #asn_db
    while left <= right do
        local mid = math.floor((left + right) / 2)
        local entry = asn_db[mid]

        if ip_num >= entry.ip_start and ip_num <= entry.ip_end then
            return entry.asn, entry.org
        elseif ip_num < entry.ip_start then
            right = mid - 1
        else
            left = mid + 1
        end
    end

    return "No ASN", "Unknown Organization"
end

-- Main dissector function for Wireshark
function asn_proto.dissector(buffer, pinfo, tree)
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)

    local src_asn, src_org = get_asn_info(src_ip)
    local dst_asn, dst_org = get_asn_info(dst_ip)

    -- Create ASN Information tree in Wireshark
    local subtree = tree:add(asn_proto, "ASN Information")
    subtree:add(src_asn_field, src_asn)
    subtree:add(src_org_field, src_org)
    subtree:add(dst_asn_field, dst_asn)
    subtree:add(dst_org_field, dst_org)
end

-- Register the dissector with Wireshark
register_postdissector(asn_proto)

-- Load the ASN database (update the path as needed)
load_asn_database("/path/to/ip2asn-v4.tsv")
-- Database available at https://iptoasn.com/data/ip2asn-v4.tsv.gz
