--[[
Wireshark Lua plugin: look up an IP address on ipinfo.io.

Adds Tools -> Check IPinfo, which prompts for an IP address and opens
https://ipinfo.io/<ip> in the default browser.
--]]

local function open_ip_info()
    new_dialog("Check IP Info", function(input)
        if not input or input == "" then
            print("check_ipinfo: no IP entered")
            return
        end
        -- accept only IPv4/IPv6 characters
        if not input:match("^%d+%.%d+%.%d+%.%d+$") and not input:match("^[%x:]+$") then
            print("check_ipinfo: invalid IP address: " .. input)
            return
        end
        browser_open_url("https://ipinfo.io/" .. input)
    end, "Enter IP Address:")
end

if gui_enabled() then
    register_menu("Check IPinfo", open_ip_info, MENU_TOOLS_UNSORTED)
end
