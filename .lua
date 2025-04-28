local HttpService = game:GetService("HttpService")
local clipboard = setclipboard or toclipboard or set_clipboard or function(text) warn("Clipboard not supported: " .. tostring(text)) end

local function toBase64(str)
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local result = ''
    local padding = 0
    local bytes = {str:byte(1, -1)}
    
    for i = 1, #bytes, 3 do
        local a, b, c = bytes[i], bytes[i+1], bytes[i+2]
        if not b then b, c, padding = 0, 0, 2
        elseif not c then c, padding = 0, 1 end
        
        local n = bit32.lshift(a, 16) + bit32.lshift(b or 0, 8) + (c or 0)
        result = result .. b64chars:sub(1 + bit32.rshift(n, 18), 1 + bit32.rshift(n, 18))
        result = result .. b64chars:sub(1 + bit32.band(bit32.rshift(n, 12), 63), 1 + bit32.band(bit32.rshift(n, 12), 63))
        result = result .. (padding > 1 and '=' or b64chars:sub(1 + bit32.band(bit32.rshift(n, 6), 63), 1 + bit32.band(bit32.rshift(n, 6), 63)))
        result = result .. (padding > 0 and '=' or b64chars:sub(1 + bit32.band(n, 63), 1 + bit32.band(n, 63)))
    end
    return result
end

local function toBase32(str)
    local b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    local result = ''
    local bits = 0
    local bitCount = 0
    
    for i = 1, #str do
        bits = bit32.lshift(bits, 8) + str:byte(i)
        bitCount = bitCount + 8
        while bitCount >= 5 do
            local index = bit32.rshift(bits, bitCount - 5) % 32 + 1
            result = result .. b32chars:sub(index, index)
            bitCount = bitCount - 5
        end
    end
    
    if bitCount > 0 then
        bits = bit32.lshift(bits, 5 - bitCount)
        local index = bit32.band(bits, 31) + 1
        result = result .. b32chars:sub(index, index)
    end
    return result
end

local function toBase16(str)
    local result = ''
    for i = 1, #str do
        result = result .. string.format('%02X', str:byte(i))
    end
    return result
end

local function xorEncrypt(str, key)
    local result = ""
    for i = 1, #str do
        local byte = string.byte(str, i)
        local keyByte = string.byte(key, (i - 1) % #key + 1)
        result = result .. string.char(bit32.bxor(byte, keyByte))
    end
    return result
end

local function generateRandomVar()
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local name = "_v"
    for i = 1, 8 do
        local rand = math.random(1, #chars)
        name = name .. chars:sub(rand, rand)
    end
    return name
end

local function detectDebugger()
    local success, result flares pcall(function()
        local gc = getgc(true)
        for _, v in pairs(gc) do
            if type(v) == "function" and islclosure(v) then
                local constants = debug.getconstants(v)
                if table.find(constants, "HttpSpy") or table.find(constants, "NotDSF") or table.find(constants, "https://api.github.com/repos/NotDSF/HttpSpy") then
                    return true
                end
            end
        end
        return false
    end)
    if success and result then
        error("HTTP Debugger detected! Execution terminated.")
    end
    if hookmetamethod then
        local success, err = pcall(function()
            local oldNamecall = hookmetamethod(game, "__namecall", function() return end)
            hookmetamethod(game, "__namecall", oldNamecall)
        end)
        if not success then
            warn("Failed to verify namecall hook: " .. tostring(err))
        end
    end
    if hookfunction and (syn or http) and (syn.request or http.request) then
        local success, err = pcall(function()
            local oldRequest = (syn or http).request
            hookfunction(oldRequest, function() return {} end)
            hookfunction(oldRequest, oldRequest)
        end)
        if not success then
            warn("Failed to verify request hook: " .. tostring(err))
        end
    end
end

local function encryptScript(scriptContent)
    detectDebugger()
    local lines = {}
    local variables = {}
    local output = ""

    for line in scriptContent:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    for _, line in ipairs(lines) do
        local newLine = line

        if line:match("^%s*local%s+[%w_]+%s*=") or line:match("^%s*[%w_]+%s*=") then
            local varName = line:match("^%s*local%s+([%w_]+)%s*=") or line:match("^%s*([%w_]+)%s*=")
            local newVarName = generateRandomVar()
            variables[varName] = newVarName
            newLine = line:gsub(varName, newVarName)
        end

        for oldVar, newVar in pairs(variables) do
            newLine = newLine:gsub("%f[%w_]" .. oldVar .. "%f[^%w_]", newVar)
        end

        newLine = newLine:gsub('"(.-)"', function(str)
            local b16 = toBase16(str)
            local b32 = toBase32(b16)
            local b64 = toBase64(b32)
            local xorEnc = xorEncrypt(b64, "xor-key")
            return string.format('decrypt("%s")', xorEnc)
        end)

        output = output .. newLine .. "\n"
    end

    local decryptFunc = [[
local function fromBase64(str)
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local result = ''
    local num = 0
    local bits = 0
    str = str:gsub('=', '')
    
    for i = 1, #str do
        local char = str:sub(i, i)
        local value = b64chars:find(char) - 1
        num = num * 64 + value
        bits = bits + 6
        if bits >= 8 then
            result = result .. string.char(bit32.rshift(num, bits - 8) % 256)
            bits = bits - 8
            num = num % bit32.lshift(1, bits)
        end
    end
    return result
end

local function fromBase32(str)
    local b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    local result = ''
    local num = 0
    local bits = 0
    
    for i = 1, #str do
        local char = str:sub(i, i)
        local value = b32chars:find(char) - 1
        num = num * 32 + value
        bits = bits + 5
        while bits >= 8 do
            result = result .. string.char(bit32.rshift(num, bits - 8) % 256)
            bits = bits - 8
            num = num % bit32.lshift(1, bits)
        end
    end
    return result
end

local function fromBase16(str)
    local result = ''
    for i = 1, #str, 2 do
        local hex = str:sub(i, i+1)
        result = result .. string.char(tonumber(hex, 16))
    end
    return result
end

local function decrypt(enc)
    local xorDec = xorEncrypt(enc, "xor-key")
    local b64Dec = fromBase64(xorDec)
    local b32Dec = fromBase32(b64Dec)
    local b16Dec = fromBase16(b32Dec)
    return b16Dec
end
]]

    return decryptFunc .. output
end

local function processScript(url, userScript)
    detectDebugger()
    local success, response = pcall(function()
        return game:HttpGet(url)
    end)

    if not success then
        warn("Failed to fetch script: " .. tostring(response))
        return
    end

    local combinedScript = response .. "\n" .. userScript
    local success, encryptedScript = pcall(encryptScript, combinedScript)
    if not success then
        warn("Failed to encrypt script: " .. tostring(encryptedScript))
        return
    end

    local success, err = pcall(clipboard, encryptedScript)
    if not success then
        warn("Failed to copy to clipboard: " .. tostring(err))
        return
    end

    print("Encrypted script copied to clipboard!")
    return encryptedScript
end

