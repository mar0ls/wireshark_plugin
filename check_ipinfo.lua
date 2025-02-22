--[[  
 * This Lua script is a Wireshark plugin that allows users to quickly look up IP address information from external sources ipinfo.io **
 *
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
 * **Tools -> Check IPinfo**  
]]


-- Function to open an IP lookup webpage
local function open_ip_info()
    -- Callback function that processes user input from the dialog box
    local function callback(input)
        -- Check if the user entered a valid IP address (non-empty string)
        if input and input ~= "" then
            local url = "https://ipinfo.io/" .. input  -- Construct the lookup URL
            local cmd  -- Variable to store the command that will open the URL

            -- Determine the operating system and set the appropriate command
            if package.config:sub(1,1) == "\\" then
                -- Windows: Use 'start' to open the URL in the default web browser
                cmd = "start " .. url
            else
                -- Get the OS name using 'uname -s' (used in Unix-like systems)
                local handle = io.popen("uname -s")  -- Open a process to execute the command
                local result = handle:read("*a")  -- Read the output of the command
                handle:close()  -- Close the process handle

                if result:match("Darwin") then
                    -- macOS: Use 'open' to launch the URL
                    cmd = "open " .. url
                else
                    -- Linux: Use 'xdg-open' to open the URL in the default browser
                    cmd = "xdg-open " .. url
                end
            end

            -- Execute the command if it was successfully determined
            if cmd then
                print("🔄 Executing command: " .. cmd)  -- Log the command to the console
                os.execute(cmd)  -- Execute the command to open the URL
            else
                print("❌ Could not determine OS")  -- Error message if OS detection fails
            end
        else
            print("❌ No IP entered")  -- Error message if no IP was entered
        end
    end

    -- Create a dialog box to prompt the user for an IP address
    local title = "Check IP Info"  -- Title of the dialog box
    new_dialog(title, callback, "Enter IP Address:")  -- Create the dialog with a text input field
end

-- Add the "Check IP" option to the Wireshark Tools menu
register_menu("Check IPinfo", open_ip_info, MENU_TOOLS_UNSORTED)
