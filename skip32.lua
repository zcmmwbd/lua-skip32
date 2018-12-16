--[[
    SKIP32 -- 32 bit block cipher based on SKIPJACK.
    Written by Greg Rose (in C), QUALCOMM Australia, 1999/04/27.
    Ported by linsy#vip.qq.com, 2018/12/15.
    In common: F-table, G-permutation, key schedule.
    Different: 24 round feistel structure.
    Based on:  Unoptimized test implementation of SKIPJACK algorithm
               Panu Rissanen <bande@lut.fi>
    SKIPJACK and KEA Algorithm Specifications
    Version 2.0
    29 May 1998
    Not copyright, no rights reserved.
]]

local _M = { }
local bit = require "bit" -- luajit required
local lshift = bit.lshift
local rshift = bit.rshift
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local mod = math.fmod
local type = type
local str_char = string.char

local ftable = {
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
};

local function g_n(key, k, w)
    local v1 = band(rshift(w, 8), 0xff)
    local v2 = band(w, 0xff)
    v1 = bxor(ftable[bxor(v2, key[mod(4 * k, 10) + 1]) + 1], v1)
    v2 = bxor(ftable[bxor(v1, key[mod(4 * k + 1, 10) + 1]) + 1], v2)
    v1 = bxor(ftable[bxor(v2, key[mod(4 * k + 2, 10) + 1]) + 1], v1)
    v2 = bxor(ftable[bxor(v1, key[mod(4 * k + 3, 10) + 1]) + 1], v2)
    return bor(lshift(v1, 8), v2)
end

-- -- key: byte[10], k (round): int, w (data): byte[2]
-- local function g_le(key, k, w)
--     local v1 = w[1] -- string, little-endian version
--     local v2 = w[2]
--     v1 = bxor(ftable[bxor(v2, key[mod(4 * k, 10) + 1]) + 1], v1)
--     v2 = bxor(ftable[bxor(v1, key[mod(4 * k + 1, 10) + 1]) + 1], v2)
--     v1 = bxor(ftable[bxor(v2, key[mod(4 * k + 2, 10) + 1]) + 1], v1)
--     v2 = bxor(ftable[bxor(v1, key[mod(4 * k + 3, 10) + 1]) + 1], v2)
--     -- return { v1, v2 }
--     w[1] = v1
--     w[2] = v2
-- end

local function fpe_skip32(key, buf, encrypt, round)
    local k, i, kstep, wl, wr
    round = round or 24

    if encrypt then
        kstep = 1
        k = 0
    else
        kstep = -1
        k = round - 1
    end

    wl = bor(lshift(buf[1], 8), buf[2])
    wr = bor(lshift(buf[3], 8), buf[4])

    for i = 1, round / 2 do
        wr = bxor(bxor(g_n(key, k, wl), k), wr)
        k = kstep + k
        wl = bxor(bxor(g_n(key, k, wr), k), wl)
        k = kstep + k
    end

    return {
        rshift(wr, 8),
        band(wr, 0xff),
        rshift(wl, 8),
        band(wl, 0xff)
    }
end

local skip32_data_to_number

local function skip32_data_to_number_le(data)
    return bor(data[1],
        lshift(data[2], 8),
        lshift(data[3], 16),
        lshift(data[4], 24))
end

local function skip32_data_to_number_be(data)
    return bor(
        lshift(data[1], 24),
        lshift(data[2], 16),
        lshift(data[3], 8),
               data[4])
end

local skip32_number_to_data

local function skip32_number_to_data_le(n)
    return {
        band(n, 0xff),
        band(rshift(n, 8), 0xff),
        band(rshift(n, 16), 0xff),
        band(rshift(n, 24), 0xff),
    }
end

local function skip32_number_to_data_be(n)
    return {
        band(rshift(n, 24), 0xff),
        band(rshift(n, 16), 0xff),
        band(rshift(n, 8), 0xff),
        band(n, 0xff),
    }
end

local function skip32_check_key(key)
    local t = type(key)
    if t == "string" then
        if #key >= 10 then
            -- transform to table
            return { key:byte(1, 10) }
        end
        return nil, "expected key length is 10 byte (80bit)"
    elseif t == "table" then
        if #key >= 10 then
            return key
        end
        return nil, "expected key length is 10 byte (80bit)"
    end
    return nil, "unexpected key type. (string/array)"
end

local function skip32_data_to_string(data)
    return str_char(unpack(data))
end

local function skip32_check_data(data)
    local t = type(data)
    if t == "string" then
        if #data == 4 then
            -- transform to table
            return { data:byte(1, 4) }, skip32_data_to_string
        end
        return nil, "expected data length is 4 byte"
    elseif t == "table" then
        if #data == 4 then
            return data
        end
        return nil, "expected data length is 4 byte"
    elseif t == "number" then
        -- transform to table
        return skip32_number_to_data(data), skip32_data_to_number
    end
    return nil, "unexpected data type. (string/array/number)"
end

-- key as a string or table, n as a number or table
local function skip32_encrypt(key, data)
    local err
    key, err = skip32_check_key(key)
    if not key then
        return nil, err or "invalid key"
    end
    data, err = skip32_check_data(data)
    if not data then
        return nil, err or "invalid data"
    end
    local ret = fpe_skip32(key, data, true)
    if err then
        -- indecate that need to transform data format
        return err(ret)
    end
    return ret
end

local function skip32_decrypt(key, data)
    local err
    key, err = skip32_check_key(key)
    if not key then
        return nil, err or "invalid key"
    end
    data, err = skip32_check_data(data)
    if not data then
        return nil, err or "invalid data"
    end
    local ret = fpe_skip32(key, data, false)
    if err then
        -- indecate that need to transform data format
        return err(ret)
    end
    return ret
end

if require "ffi".abi("le") then
    -- little-endian
    skip32_number_to_data = skip32_number_to_data_le
    skip32_data_to_number = skip32_data_to_number_le
else
    -- big-endian
    skip32_number_to_data = skip32_number_to_data_be
    skip32_data_to_number = skip32_data_to_number_be
end

_M.fpe_skip32 = fpe_skip32
_M.encrypt = skip32_encrypt
_M.decrypt = skip32_decrypt
_M.data_to_number = skip32_data_to_number
_M.number_to_data = skip32_number_to_data
_M.check_key = skip32_check_key
_M.check_data = skip32_check_data

-- test:
-- -- encrypt: 0xB4B2C7F0
-- -- decrypt: 0x04030201
-- local testkey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }
-- local testdata = { 1, 2, 3, 4 }
-- local e = fpe_skip32(testkey, testdata, true)
-- print(unpack(e)) -- =>   240 199 178 180
-- print(unpack(skip32_encrypt(testkey, testdata))) -- =>   240 199 178 180
-- print(unpack(skip32_encrypt("\1\2\3\4\5\6\7\x08\x09\0", testdata))) -- =>   240 199 178 180
-- print(skip32_encrypt(testkey, "\1\2\3\4"):byte(1, 4)) -- =>   240 199 178 180
-- print(skip32_encrypt(testkey, 0x04030201)) -- => -1263351824 (0xB4B2C7F0)
-- local d = fpe_skip32(testkey, e, false)
-- print(unpack(d)) -- =>   1   2   3   4


return _M
