--[[
The MIT License (MIT)

Copyright (c) 2015 xuwaters@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]


local M = { _TYPE = 'module', _NAME = 'sfsio', _VERSION = '1.0.0' }

-- Types
M.T_NULL = 0;
M.T_BOOL = 1;
M.T_BYTE = 2;
M.T_SHORT = 3;
M.T_INT = 4;
M.T_LONG = 5;
M.T_FLOAT = 6;
M.T_DOUBLE = 7;
M.T_UTF_STRING = 8;
M.T_BOOL_ARRAY = 9;
M.T_BYTE_ARRAY = 10;
M.T_SHORT_ARRAY = 11;
M.T_INT_ARRAY = 12;
M.T_LONG_ARRAY = 13;
M.T_FLOAT_ARRAY = 14;
M.T_DOUBLE_ARRAY = 15;
M.T_UTF_STRING_ARRAY = 16;
M.T_SFS_ARRAY = 17;
M.T_SFS_OBJECT = 18;
M.T_CLASS = 19;

M.Encoding = ENC_UTF_8

-- Helpers

local binDecode_NULL = function( tvbuffer, offset )
  return nil, offset
end

local binDecode_BOOL = function( tvbuffer, offset )
  local val = tvbuffer(offset, 1):uint()
  return (val == 1), offset + 1
end

local binDecode_BYTE = function( tvbuffer, offset )
  local val = tvbuffer(offset, 1):uint()
  return val, offset + 1
end

local binDecode_SHORT = function( tvbuffer, offset )
  local val = tvbuffer(offset, 2):int()
  return val, offset + 2
end

local binDecode_INT = function( tvbuffer, offset )
  local val = tvbuffer(offset, 4):int()
  return val, offset + 4
end

-- Int64 object, https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Int64.html
local binDecode_LONG = function( tvbuffer, offset )
  local val = tvbuffer(offset, 8):int64()
  -- return val:tonumber(), offset + 8
  return tostring(val), offset + 8
end

local binDecode_FLOAT = function( tvbuffer, offset )
  local val = tvbuffer(offset, 4):float()
  return val, offset + 4
end

local binDecode_DOUBLE = function( tvbuffer, offset )
  local val = tvbuffer(offset, 8):float()
  return val, offset + 8
end

local binDecode_UTF_STRING = function( tvbuffer, offset )
  local strlen
  strlen, offset = binDecode_SHORT(tvbuffer, offset)
  if strlen < 0 then
    error("string length out of range: " .. tostring(strlen))
  end
  local val = tvbuffer(offset, strlen):string(M.Encoding)
  return val, offset + strlen
end

-- array helper
local getTypeArraySize = function( tvbuffer, offset )
  local count
  count, offset = binDecode_SHORT(tvbuffer, offset)
  if count < 0 then
    error("array count out of range: " .. count)
  else
    return count, offset
  end
end

local decodeArray = function( tvbuffer, offset, decoder )
  local count
  count, offset = getTypeArraySize(tvbuffer, offset)
  local arr = {}
  for i=1,count do
    local val
    val, offset = decoder(tvbuffer, offset)
    arr[i] = val
  end
  return arr, offset
end


local binDecode_BOOL_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_BOOL)
end

-- return tvbuffer_range
local binDecode_BYTE_ARRAY = function( tvbuffer, offset )
  local count
  count, offset = getTypeArraySize(tvbuffer, offset)
  local val = tvbuffer(offset, count)
  return val, offset + count
end

local binDecode_SHORT_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_SHORT)
end

local binDecode_INT_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_INT)
end

local binDecode_LONG_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_LONG)
end

local binDecode_FLOAT_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_FLOAT)
end

local binDecode_DOUBLE_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_DOUBLE)
end

local binDecode_UTF_STRING_ARRAY = function( tvbuffer, offset )
  return decodeArray(tvbuffer, offset, binDecode_UTF_STRING)
end

local binDecode_SFS_ARRAY = function( tvbuffer, offset )
  local val
  val, offset = M.decodeSFSArray(tvbuffer, offset - 1)
  return val, offset
end

local binDecode_SFS_OBJECT = function( tvbuffer, offset )
  local val
  val, offset = M.decodeSFSObject(tvbuffer, offset - 1)
  return val, offset
end

local binDecode_CLASS = function( tvbuffer, offset )
  local val
  val, offset = binDecode_SFS_OBJECT(tvbuffer, offset)
  -- special key: $C, $F
  return val, offset
end

-- Funtions

function M.decodeObject( tvbuffer, offset )
  -- type
  local t = tvbuffer(offset, 1):int()
  offset = offset + 1
  if t == M.T_NULL then
    return binDecode_NULL(tvbuffer, offset)
  elseif t == M.T_BOOL then
    return binDecode_BOOL(tvbuffer, offset)
  elseif t == M.T_BYTE then
    return binDecode_BYTE(tvbuffer, offset)
  elseif t == M.T_SHORT then
    return binDecode_SHORT(tvbuffer, offset)
  elseif t == M.T_INT then
    return binDecode_INT(tvbuffer, offset)
  elseif t == M.T_LONG then
    return binDecode_LONG(tvbuffer, offset)
  elseif t == M.T_FLOAT then
    return binDecode_FLOAT(tvbuffer, offset)
  elseif t == M.T_DOUBLE then
    return binDecode_DOUBLE(tvbuffer, offset)
  elseif t == M.T_UTF_STRING then
    return binDecode_UTF_STRING(tvbuffer, offset)
  elseif t == M.T_BOOL_ARRAY then
    return binDecode_BOOL_ARRAY(tvbuffer, offset)
  elseif t == M.T_BYTE_ARRAY then
    return binDecode_BYTE_ARRAY(tvbuffer, offset)
  elseif t == M.T_SHORT_ARRAY then
    return binDecode_SHORT_ARRAY(tvbuffer, offset)
  elseif t == M.T_INT_ARRAY then
    return binDecode_INT_ARRAY(tvbuffer, offset)
  elseif t == M.T_LONG_ARRAY then
    return binDecode_LONG_ARRAY(tvbuffer, offset)
  elseif t == M.T_FLOAT_ARRAY then
    return binDecode_FLOAT_ARRAY(tvbuffer, offset)
  elseif t == M.T_DOUBLE_ARRAY then
    return binDecode_DOUBLE_ARRAY(tvbuffer, offset)
  elseif t == M.T_UTF_STRING_ARRAY then
    return binDecode_UTF_STRING_ARRAY(tvbuffer, offset)
  elseif t == M.T_SFS_ARRAY then
    return binDecode_SFS_ARRAY(tvbuffer, offset)
  elseif t == M.T_SFS_OBJECT then
    return binDecode_SFS_OBJECT(tvbuffer, offset)
  else
    error("Unknown object type: " .. t)
  end
end

-- @return object, offset
function M.decodeSFSObject(tvbuffer, offset)
  -- Type
  local t = tvbuffer(offset, 1):int()
  offset = offset + 1
  if t ~= M.T_SFS_OBJECT then
    error("SFSObject type invalid: " .. t)
  end
  -- Size
  local count = tvbuffer(offset, 2):int()
  offset = offset + 2
  if count < 0 then
    error("object size out of range " .. count)
  end

  local obj = {}
  for i=1,count do
    -- key
    local keylen = tvbuffer(offset, 2):int()
    offset = offset + 2
    if keylen < 0 or keylen > 255 then
      error("key length out of range " .. keylen)
    end
    local key = tvbuffer(offset, keylen):string(M.Encoding)
    offset = offset + keylen
    -- Value
    local val
    val, offset = M.decodeObject(tvbuffer, offset)
    obj[key] = val
  end

  return obj, offset
end

-- @return array, offset
function M.decodeSFSArray(tvbuffer, offset)
  -- Type
  local t = tvbuffer(offset, 1):int()
  offset = offset + 1
  if t ~= M.T_SFS_ARRAY then
    error("SFSArray type invalid: " .. t)
  end

  -- Size
  local count = tvbuffer(offset, 2):int()
  offset = offset + 2
  if count < 0 then
    error("array size out of range: " .. count)
  end
  -- Value
  local arr = {}
  for i=1, count do
    local val
    val, offset = M.decodeObject(tvbuffer, offset)
    arr[i] = val
  end
  return arr, offset
end

return M
