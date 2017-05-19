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

do

  local sfs_ports = { 9933, 9339 }

  local deflate = require "deps.deflatelua"
  local sfsio = require "deps.sfsio"
  local json = require "deps.json"

  local sfs_proto = Proto("sfs", "SFS Protocol Analysis")

  local F_marker = ProtoField.uint8("sfs.marker", "sfs.marker", base.HEX)
  local F_marker_binary = ProtoField.uint8("sfs.marker.binary", "sfs.marker.binary  ", base.HEX, nil, 0x80)
  local F_marker_encrypt = ProtoField.uint8("sfs.marker.encrypt", "sfs.marker.encrypt ", base.HEX, nil, 0x40)
  local F_marker_compress = ProtoField.uint8("sfs.marker.compress", "sfs.marker.compress", base.HEX, nil, 0x20)
  local F_marker_bluebox = ProtoField.uint8("sfs.marker.bluebox", "sfs.marker.bluebox ", base.HEX, nil, 0x10)
  local F_marker_bigsize = ProtoField.uint8("sfs.marker.bigsize", "sfs.marker.bigsize ", base.HEX, nil, 0x08)
  local F_data_length = ProtoField.uint32("sfs.data_length", "sfs.data_length", base.DEC)
  local F_module = ProtoField.uint8("sfs.module", "sfs.module", base.DEC)
  local F_action = ProtoField.uint8("sfs.action", "sfs.action", base.DEC)
  local F_data = ProtoField.bytes("sfs.data", "sfs.data")
  local F_decompressed = ProtoField.bytes("sfs.decompressed", "sfs.decompressed")
  local F_string = ProtoField.string("sfs.p.string", "sfs.p.string")
  local F_ustring = ProtoField.string("sfs.p.ustring", "sfs.p.ustring")
  local F_int32 = ProtoField.int32("sfs.p.int32", "sfs.p.int32", base.DEC)
  local F_hex32 = ProtoField.uint32("sfs.p.hex32", "sfs.p.hex32", base.HEX)
  local F_int16 = ProtoField.int32("sfs.p.int16", "sfs.p.int16", base.DEC)
  local F_int8 = ProtoField.int32("sfs.p.int8", "sfs.p.int8", base.DEC)
  local F_uint32 = ProtoField.int32("sfs.p.uint32", "sfs.p.uint32", base.DEC)
  local F_uint16 = ProtoField.int32("sfs.p.uint16", "sfs.p.uint16", base.DEC)
  local F_uint8 = ProtoField.int32("sfs.p.uint8", "sfs.p.uint8", base.DEC)
  local F_double = ProtoField.double("sfs.p.double", "sfs.p.double")
  local F_float = ProtoField.float("sfs.p.float", "sfs.p.float")
  local F_json = ProtoField.string("sfs.json", "sfs.json")


  -- add the fields to the protocol
  sfs_proto.fields = {
    F_marker,
    F_marker_binary, F_marker_encrypt, F_marker_compress, F_marker_bluebox, F_marker_bigsize,
    F_data_length, F_module, F_action, F_data, F_decompressed,
    F_string, F_ustring,
    F_int32, F_int16, F_int8, F_uint32, F_uint16, F_uint8,
    F_hex32,
    F_double, F_float,
    F_json,
  }

  local f_ip_src = Field.new("ip.src")
  local f_tcp_srcport = Field.new("tcp.srcport")
  local f_tcp_dstport = Field.new("tcp.dstport")
  local f_tcp_stream = Field.new("tcp.stream")
  local f_tcp_seq = Field.new("tcp.seq")

  local ip_src
  local tcp_srcport = 0
  local tcp_dstport = 0

  -- local idx = 0
  local direction = ""

  local direction_type = ""

  local Actions = {}

  local function hex_value(val)
    if val >= string.byte('0') and val <= string.byte('9') then
      return val - string.byte('0')
    elseif val >= string.byte('a') and val <= string.byte('z') then
      return 10 + val - string.byte('a')
    elseif val >= string.byte('A') and val <= string.byte('Z') then
      return 10 + val - string.byte('A')
    end
    return val
  end

  local function get_bytes_from_str(str)
    local len = string.len(str)
    local input_str = {}
    for idx=1,len, 2 do
      local val = hex_value(string.byte(str, idx)) * 16 + hex_value(string.byte(str, idx+1))
      input_str[#input_str+1] = string.char(val)
      print (hex_value(string.byte(str, idx)) * 16 .. " " .. hex_value(string.byte(str, idx+1)) .. " = " .. string.format('%02x', val))
    end
    input_str = table.concat(input_str)
    return input_str
  end

  local function sfs_dissect_payload(tvbuffer, pinfo, treeitem, offset)
    local val
    val, offset = sfsio.decodeObject(tvbuffer, offset)
    local jsonstr = json:encode(val)

    local jsonbytes = ByteArray.new()
    local jsonlen = string.len(jsonstr)
    jsonbytes:set_size(jsonlen)
    for i=1,jsonlen do
      jsonbytes:set_index(i-1, string.byte(jsonstr,i))
    end
    --[[
        local jsonhex, _ = string.gsub(jsonstr, ".", function (k) return string.format("%02x", k:byte(1,1)) end)
        local jsonbytes = ByteArray.new(jsonhex)
        ]]
    local jsontvb = ByteArray.tvb(jsonbytes, "DecodedJson")
    local valtree = treeitem:add(F_json, jsontvb(0, jsontvb:len()))
  end

  local function sfs_dissector_one(tvbuffer, pinfo, treeitem, offset)
    local orig_offset = offset

    local packet_header = tvbuffer(offset, 1)
    offset = offset + 1
    local payload_length = tvbuffer(offset, 2)
    offset = offset + 2
    local pdu_length = 1 + 2 + payload_length:uint()
    local buff_len = tvbuffer:len() - offset

    if buff_len < payload_length:uint() then
      info("payload too small, buff_len = " .. buff_len)
      return 0
    end

    local subtreeitem = treeitem:add(sfs_proto, tvbuffer)

    local headertree = subtreeitem:add(F_marker, packet_header)
    -- header
    headertree:add(F_marker_binary, packet_header)
    headertree:add(F_marker_encrypt, packet_header)
    headertree:add(F_marker_compress, packet_header)
    headertree:add(F_marker_bluebox, packet_header)
    headertree:add(F_marker_bigsize, packet_header)

    -- data length
    subtreeitem:add(F_data_length, payload_length)

    -- decompress if needed
    local compress = bit32.band(packet_header:uint(), 0x20)

    -- data
    local content_len = payload_length:uint()
    local content_offset = offset
    local dataitem = subtreeitem:add(F_data, tvbuffer(offset, content_len))
    offset = offset + content_len

    -- check compress
    if compress ~= 0 then
      local begin_idx = content_offset
      local end_idx = begin_idx + content_len - 1
      local input_str = {}
      for buff_idx = begin_idx, end_idx do
        input_str[#input_str + 1] = string.char(tvbuffer(buff_idx, 1):uint())
      end
      input_str = table.concat(input_str)
      -- decompress
      local output_table = {}
      local output_fun = function(byte)
        output_table[#output_table + 1] = string.format("%02x",byte)
      end
      deflate.inflate_zlib {
        input = input_str,
        output = output_fun
      }
      local output_str = table.concat(output_table)
      -- print("output_str = " .. output_str)
      local decompressed = ByteArray.new(output_str)
      local tvb = ByteArray.tvb(decompressed, "decompressed")
      dataitem = subtreeitem:add(F_decompressed, tvb(0, tvb:len()))
      sfs_dissect_payload(tvb, pinfo, subtreeitem, 0)
    else
      -- dissect content
      sfs_dissect_payload(tvbuffer, pinfo, subtreeitem, content_offset)
    end

    return offset - orig_offset

  end

  local function sfs_decode_payload(tvbuffer)
    local buff_len = tvbuffer:len()
    local buff = ByteArray.new()
    buff:set_size(buff_len)

    local idx
    for idx = 0, buff_len-1 do
      local val = tvbuffer(idx, 1):uint()
      val = bit32.bxor(val, 6)
      buff:set_index(idx, val)
    end
    local ret = ByteArray.tvb(buff, "Decoded")
    return ret
  end

  local function sfs_dissector(tvbuffer, pinfo, treeitem)

    local is_server_port = function (port)
      for _, val in ipairs(sfs_ports) do
        if val == port then
          return true
        end
      end
      return false
    end

    ip_src = ""
    if f_ip_src() then
      ip_src = tostring(f_ip_src())
    end

    tcp_srcport = 0
    if f_tcp_srcport() then
      tcp_srcport = f_tcp_srcport().value or 0
    else
      tcp_srcport = pinfo.src_port
    end

    tcp_dstport = 0
    if f_tcp_dstport() then
      tcp_dstport = f_tcp_dstport().value or 0
    else
      tcp_dstport = pinfo.dst_port
    end

    direction = ""
    direction_type = ""
    if tcp_srcport ~= 0 and tcp_dstport ~= 0 then
      if is_server_port(tcp_srcport) then
        direction = "Response <--"
        direction_type = "response"
      elseif is_server_port(tcp_dstport) then
        direction = "Request  -->"
        direction_type = "request"
      end
    end

    local direction_len = direction:len()
    local protocol_name = "SFS"

    -- check header
    local header = tvbuffer(0, 1):uint()
    if bit32.band(header, 0x07) ~= 0 then
      print("ignore packet, id = " .. pinfo.number)
      return 0
    end

    local totallen = tvbuffer:len()
    local offset = 0

    -- if offset < totallen then
    while offset < totallen do
      local payload_length = tvbuffer(offset + 1, 2):uint()
      local available = totallen - offset - 1 - 2
      if payload_length > available then
        pinfo.desegment_len = payload_length - available
        pinfo.desegment_offset = offset
        return
      end
      local delta_offset = sfs_dissector_one(tvbuffer, pinfo, treeitem, offset)
      if delta_offset <= 0 then
        print("delta_offset = " .. delta_offset)
        -- return
        break
      end
      offset = offset + delta_offset
    end

    pinfo.cols.protocol = protocol_name
    pinfo.cols.info = direction
  end

  -- declare the fields we need to read
  function sfs_proto.dissector(tvbuffer, pinfo, treeitem)
    return sfs_dissector(tvbuffer, pinfo, treeitem)
  end

  local tcp_dissector_table = DissectorTable.get("tcp.port")
  for _, port in ipairs(sfs_ports) do
    tcp_dissector_table:add(port, sfs_proto)
  end

  print("Version = " .. _VERSION)

end
