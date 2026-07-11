--[[
Wireshark Lua plugin: offline ASN lookup.

Enriches every packet with source/destination ASN and organization,
looked up in a local copy of the iptoasn.com database (IPv4 TSV).

Download https://iptoasn.com/data/ip2asn-v4.tsv.gz, extract it and
set ASN_DB_PATH below.
--]]

local ASN_DB_PATH = "/path/to/ip2asn-v4.tsv"

local asn_proto = Proto("ASN_Info", "ASN Information")

local src_asn_field = ProtoField.string("asn_info.src", "Source ASN")
local src_org_field = ProtoField.string("asn_info.src_org", "Source Organization")
local dst_asn_field = ProtoField.string("asn_info.dst", "Destination ASN")
local dst_org_field = ProtoField.string("asn_info.dst_org", "Destination Organization")

asn_proto.fields = { src_asn_field, src_org_field, dst_asn_field, dst_org_field }

-- sorted array of { ip_start, ip_end, asn, org }
local asn_db = {}

local function ip_to_number(ip)
    local o1, o2, o3, o4 = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then return nil end
    return (tonumber(o1) * 256^3) + (tonumber(o2) * 256^2) + (tonumber(o3) * 256) + tonumber(o4)
end

local private_ranges = {
    { ip_to_number("10.0.0.0"),    ip_to_number("10.255.255.255") },
    { ip_to_number("172.16.0.0"),  ip_to_number("172.31.255.255") },
    { ip_to_number("192.168.0.0"), ip_to_number("192.168.255.255") },
}

local function is_private_ip(ip_num)
    for _, range in ipairs(private_ranges) do
        if ip_num >= range[1] and ip_num <= range[2] then
            return true
        end
    end
    return false
end

local function load_asn_database(filename)
    local file = io.open(filename, "r")
    if not file then
        print("check_asn: ASN file not found: " .. filename)
        return
    end

    for line in file:lines() do
        line = line:gsub("\r", "")
        local ip_start, ip_end, asn, _, org = line:match("([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t(.+)")
        if ip_start then
            local ip_start_num = ip_to_number(ip_start)
            local ip_end_num = ip_to_number(ip_end)
            if ip_start_num and ip_end_num then
                asn_db[#asn_db + 1] = {
                    ip_start = ip_start_num,
                    ip_end = ip_end_num,
                    asn = "AS" .. asn,
                    org = org,
                }
            end
        else
            print("check_asn: invalid line in ASN file: " .. line)
        end
    end
    file:close()

    table.sort(asn_db, function(a, b) return a.ip_start < b.ip_start end)
    print("check_asn: loaded " .. #asn_db .. " ASN entries")
end

-- binary search over sorted, non-overlapping ranges
local function get_asn_info(ip)
    local ip_num = ip_to_number(ip)
    if not ip_num then return nil end

    if is_private_ip(ip_num) then
        return "Private IP", "Local Network"
    end

    local left, right = 1, #asn_db
    while left <= right do
        local mid = (left + right) // 2
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

function asn_proto.dissector(buffer, pinfo, tree)
    local src_asn, src_org = get_asn_info(tostring(pinfo.src))
    local dst_asn, dst_org = get_asn_info(tostring(pinfo.dst))
    if not src_asn and not dst_asn then return end  -- non-IPv4 packet

    local subtree = tree:add(asn_proto, "ASN Information")
    if src_asn then
        subtree:add(src_asn_field, src_asn)
        subtree:add(src_org_field, src_org)
    end
    if dst_asn then
        subtree:add(dst_asn_field, dst_asn)
        subtree:add(dst_org_field, dst_org)
    end
end

register_postdissector(asn_proto)

load_asn_database(ASN_DB_PATH)
