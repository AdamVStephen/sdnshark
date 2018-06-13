-- SDN Lua plugin
-- packet dissector for ITER SDN Synchronous Databus Network protocol.
--
-- https://github.com/AdamVStephen/sdnshark
--
-- Copyright 2018 Adam Vercingetorix Stephen
--
-- References
--
-- https://osqa-ask.wireshark.org/questions/63194/lua-dissector-from-xml-file
-- https://osqa-ask.wireshark.org/questions/4639/extracting-soap-xml-payload

--[[Use this snipet of code to test your dissectorn. You can test your dissector without wireshark by running the dissector script directly!]]

if disable_lua == nil and not _WIREBAIT_ON_ then  --disable_lua == nil checks if this script is being run from wireshark.
  local wirebait = require("wirebait");
  local dissector_tester = wirebait.plugin_tester.new({dissector_filepath="/home/astephen/git-wd/sdnshark/sdnV2.lua", only_show_dissected_packets=true});
  local sdn_hex_data = "0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF"
  .. "FF FF F2 F8 22 FD DD 04  FC E6 8A A6 80 00 00 00  00 00 00 01 57 69 72 65  62 61 69 74 00 62 79 20" 
  .. "4D 61 72 6B 6F 50 61 75  6C 30 00 00 AA BB CC 11  22 33 C0 A8 0E 1C AB CD  EF 12 34 56 78 90 AB CD" 
  .. "EF 12 34 56 78 90 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" 
  .. "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" 
  .. "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00";
  --[[Note that the white spaces don't matter in the hex string.]]
  
  --[[Two options here:
        - call dissector_tester:dissectHexData() to dissect hex data from a string (no pcap needed) 
        - call dissector_tester:dissectPcap() to dissect packets from a pcap file]]
  dissector_tester:dissectHexData(sdn_hex_data)    --dissection from hex data contained in a string
  return
end

print("SDN protocol ...")

local sdn = Proto("sdn", "ITER Synchronous Databus Network Protocol")

local headerFieldLengths = {
   ["h_header_uid"] = 4,
   ["h_header_version"] = 4,
   ["h_header_size"] = 4,
   ["h_topic_uid"] = 4,
   ["t_topic_version"] = 4,
   ["h_topic_size"] = 4,
   ["h_topic_counter"] = 8,
   ["h_send_time"] = 8,
   ["h_recv_time"] = 8
}

local h_header_uid = ProtoField.string("sdn.header_uid", "String");
local h_header_version = ProtoField.string("sdn.header_version", "String");
local h_header_size = ProtoField.uint32("sdn.header_size", "32-bit uint");
local h_topic_uid = ProtoField.uint32("sdn.topic_uid", "32-bit uint");
local h_topic_version = ProtoField.uint32("sdn.topic_version", "32-bit uint");
local h_topic_size = ProtoField.uint32("sdn.topic_size", "32-bit uint");
local h_topic_counter = ProtoField.uint64("sdn.topic_counter", "64-bit uint");
local h_send_time = ProtoField.uint64("sdn.send_time", "64-bit uint");
local h_recv_time = ProtoField.uint64("sdn.recv_time", "64-bit uint");

sdn.fields = {h_header_uid, h_header_version, h_header_size,
	      h_topic_uid, h_topic_version, h_topic_size, h_topic_counter,
	      h_send_time, h_recv_time};

local function decodeSdnHeader(buf)
   packetsize = buf:len()
--   print("decoding sdn header of size "..packetsize)
end

-- Decode SDN buffer
-- TODO: extension for fragmentation

local function decode(buf, packet_info, root_tree)
   local t = root_tree:add(sdn, buf(0,buf:len()))

   local pos = 0
   local flen = 0

   flen = headerFieldLengths["h_header_uid"];
   t:add(h_header_uid, buf(pos,flen)); pos = pos + flen;

   flen = headerFieldLengths["h_header_version"];   
   t:add(h_header_version, buf(pos,flen)); pos = pos + flen;

   flen = headerFieldLengths["h_header_size"];   
   t:add(h_header_size, buf(pos,flen)); pos = pos + flen;

   flen = headerFieldLengths["h_topic_uid"];   
   t:add(h_topic_uid, buf(pos,flen)); pos = pos + flen;
   
   print("pos "..pos.." flen "..flen)

   flen = headerFieldLengths["h_topic_version"];   
   t:add(h_topic_version, buf(pos,flen)); pos = pos + flen;

   --[[
   

   flen = headerFieldLengths["h_topic_size"];   
   t:add(h_topic_size, buf(pos,flen)); pos = pos + flen;


   flen = headerFieldLengths["h_topic_counter"];   
   t:add(h_topic_counter, buf(pos,flen)); pos = pos + flen;

   flen = headerFieldLengths["h_send_time"];   
   t:add(h_send_time, buf(pos,flen)); pos = pos + flen;

   flen = headerFieldLengths["h_recv_time"];   
   t:add(h_recv_time, buf(pos,flen)); pos = pos + flen;
   ]]--

   
end

function sdn.dissector(buf,pkt,root)
   pkt.cols.protocol =  sdn.name
   if not wirebait then
      print()
--      pkt.cols.info:clear()
--      pkt.cols.info:append(pkt.src_port.."->"..pkt.dst_port.." ")
   end

   local origbuf = buf
  local totalconsumed = 0
  decode(buf, pkt, root)

end

ports_table = DissectorTable.get("udp.port");
ports_table:add(20001, sdn);

print("SDN loaded")
