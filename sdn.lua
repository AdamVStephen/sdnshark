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
  local dissector_tester = wirebait.plugin_tester.new({dissector_filepath="sdn.lua", only_show_dissected_packets=true});
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


print("SDN protocol - discovering packets...")

local sdnTopics = {};
sdnTopics[#sdnTopics+1] = 1234;
sdnTopics[#sdnTopics+1] = 4321;

local dataTypeSizes = {
   ["uint64"] = 8,
   ["uint32"] = 4,
   ["char"] = 1
};

local xml = require("xmlSimple").newParser()

local sdnXml = [[
<message group="status" qualifier="shutdown" schemaVersion="1.0">
 <participant hostName="lorien" pid="1308" role="publisher">
  <topic name="sdn-one-pps" uid="38900" version="1" size="188" mapping="239.0.100.1:20001">
   <attributes><attribute name="time" dataType="uint64"/>
   <attribute name="time.sec" dataType="uint32"/>
   <attribute name="time.nsec" dataType="uint32"/> 
   <attribute name="time.iso8601" dataType="char" multiplicity="32"/>
   <attribute name="valid" dataType="uint32"/>
   <attribute name="valid.str" dataType="char" multiplicity="32"/>
   <attribute name="identifier" dataType="uint64"/>
   <attribute name="periodicity" dataType="uint64"/>
   <attribute name="reserved" dataType="char" multiplicity="88"/>
   </attributes>
  </topic>
 </participant>
</message>]]

local sdnParsed = xml:ParseXmlText(sdnXml)

--print("mapping "..sdnParsed.message.participant.topic["@mapping"])

local n_sdn_topics = 0;
local n_sdnDisc_packets = 0;
local n_sdn_packets = 0;

local function decodeSdnHeader(buf)
   packetsize = buf:len()
--   print("decoding sdn header of size "..packetsize)
end

local p_sdn = Proto("sdn", "ITER Synchronous Databus Network Protocol")


local f_bytes = ProtoField.bytes("sdn.bytes", "bytes");
local f_bool = ProtoField.bool("sdn.bool", "Boolean"); local f_uint8 =
ProtoField.uint8("sdn.uint8", "8-bit uint"); local f_uint16 =
ProtoField.uint16("sdn.uint16", "16-bit uint"); local f_uint24 =
ProtoField.uint24("sdn.uint24", "24-bit uint"); local f_uint32 =
ProtoField.uint32("sdn.uint32", "32-bit uint"); local f_uint64 =
ProtoField.uint64("sdn.uint64", "64-bit uint"); local f_int8 =
ProtoField.int8("sdn.int8", "8-bit int"); local f_int16 =
ProtoField.int16("sdn.int16", "16-bit int"); local f_int24 =
ProtoField.int24("sdn.int24", "24-bit int"); local f_int32 =
ProtoField.int32("sdn.int32", "32-bit int"); local f_int64 =
ProtoField.int64("sdn.int64", "64-bit int"); local f_float =
ProtoField.float("sdn.float", "Float"); local f_double =
ProtoField.double("sdn.double", "Double"); local f_string =
ProtoField.string("sdn.string", "String"); local f_stringz =
ProtoField.stringz("sdn.stringz", "Stringz"); local f_ether =
ProtoField.ether("sdn.ether", "ethernet");

local f_ipv4 = ProtoField.ipv4("sdn.ipv4", "IPv4");
local f_guid = ProtoField.guid("sdn.guid", "GUID");

p_sdn.fields = {f_bool, 
  f_uint8, f_uint16, f_uint24, f_uint32, f_uint64, 
  f_int8, f_int16, f_int24, f_int32, f_int64, 
  f_float, f_double, 
  f_string, f_stringz, 
  f_ether, f_bytes, f_ipv4, f_guid,};

function p_sdn.dissector(buffer, packet_info, root_tree)
  packet_info.cols.protocol = "SDNv2";
  main_tree = root_tree:add(p_sdn, buffer(0,86))
  
  header_tree = main_tree:add(buffer(0,48), "Header:");
  header_uid_tree = header_tree:add(buffer(0,4), "header_uid");
  header_uid_tree:add(f_bytes, buffer(0,4));
  header_uid_tree:add(f_string, buffer(0,4));
  header_version_tree = header_tree:add(buffer(4,4), "header_version");
  header_version_tree:add(f_bytes, buffer(4,4));
  header_size_tree = header_tree:add(buffer(8,4), "header_size");
  header_size_tree:add(f_bytes, buffer(8,4));  
  header_size_tree:add(f_uint32, buffer(8,4));
  topic_uid_tree = header_tree:add(buffer(12,4), "topic_uid");
  topic_uid_tree:add(f_bytes, buffer(12,4));
  topic_uid_tree:add(f_uint32, buffer(12,4));
  topic_version_tree = header_tree:add(buffer(16,4), "topic_version");
  topic_version_tree:add(f_bytes, buffer(16,4));
  topic_version_tree:add(f_uint32, buffer(16,4));
end


local sdnDisc = Proto("DDN", "ITER Synchronous Databus Network Discovery Protocol")

function sdnDisc.dissector(buffer, packet_info, root_tree)
   n_sdnDisc_packets = n_sdnDisc_packets + 1
--   print("string 3.14 "..buffer:raw());

   local discPayload = xml:ParseXmlText(buffer:raw()) 

   local sdnXml = [[<message group="status" qualifier="shutdown" schemaVersion="1.0">
<participant 
hostName="lorien" 
pid="1308" 
role="publisher">
<topic name="sdn-one-pps" uid="38900" version="1" size="188" mapping="239.0.100.1:20001">
<attributes>
<attribute name="time" dataType="uint64"/>
<attribute name="time.sec" dataType="uint32"/>
<attribute name="time.nsec" dataType="uint32"/>
<attribute name="time.iso8601" dataType="char" multiplicity="32"/>
<attribute name="valid" dataType="uint32"/>
<attribute name="valid.str" dataType="char" multiplicity="32"/>
<attribute name="identifier" dataType="uint64"/>
<attribute name="periodicity" dataType="uint64"/>
<attribute name="reserved" dataType="char" multiplicity="88"/>
</attributes>
</topic>
</participant>
</message>]]

-- Map parsed information into the interface
      packet_info.cols.protocol = "SDN-DISC";
   payload_size = buffer:len()
--   ms,me  = string.find(buffer.to_Str(), '</message>');
--   if ms then payload_size = me end
   main_tree = root_tree:add(sdnDisc, buffer(0,buffer:len()));

-- Parse participant
   local hostName = discPayload.message.participant["@hostName"];
   local pid = discPayload.message.participant["@pid"];
   local role = discPayload.message.participant["@role"];
   header_tree = main_tree:add(buffer(0,payload_size), "SDN Discovery ");
   header_tree = main_tree:add(buffer(0,payload_size), "Host: "..hostName);
   header_tree = main_tree:add(buffer(0,payload_size), "Pid : "..pid);
   header_tree = main_tree:add(buffer(0,payload_size), "Role: "..role);
-- Parse topic
   local topic = discPayload.message.participant.topic["@name"];
   local topic_uid = discPayload.message.participant.topic["@uid"];
   local topic_size = discPayload.message.participant.topic["@size"];
   local topic_mapping = discPayload.message.participant.topic["@mapping"];
   header_tree = main_tree:add(buffer(0,payload_size), "Topic: "..topic);
   header_tree = main_tree:add(buffer(0,payload_size), "Size: "..topic_size);
   header_tree = main_tree:add(buffer(0,payload_size), "Mapping: "..topic_mapping);
-- Parse and handle mapping -> mcast, and register on this port for SDN protocol
   match = string.gmatch(topic_mapping, "([^:]+)");
   local mcast_group = match()
   local mcast_port = match() + 0;
   header_tree = main_tree:add(buffer(0,payload_size), "Mcast Group: "..mcast_group);
   header_tree = main_tree:add(buffer(0,payload_size), "Mcast Port: "..mcast_port);
   -- and register protocol
   ptable = DissectorTable.get("udp.port");
   ptable:add(mcast_port, p_sdn);
   -- FIXME : the count will duplicate for multiple redundant discovery.
   n_sdn_topics = n_sdn_topics + 1
-- Iterate over the payload
   attrs = discPayload.message.participant.topic.attributes:children();
   sz = 0
   index = 1
   while sz < (topic_size + 0) do
      name = attrs[index]["@name"];
      dataType = attrs[index]["@dataType"];
      multiplicity = attrs[index]["@multiplicity"];
      if not multiplicity then multiplicity = 1 end
      sz = sz + dataTypeSizes[dataType] * multiplicity;
      index = index + 1;
--      print("Name "..name.."Type "..dataType.."Multi "..multiplicity.." Sz "..sz);
      header_tree = main_tree:add(buffer(0,payload_size), "Attribute <"..name.."> DataType: "..dataType.."["..multiplicity.."]");
--   print("< "..attrs[index]["@name"]);
--   print("@ "..attrs[index]["@dataType"]);
--   print("@ "..attrs[index]["@multiplicity"]);
--   print("< "..attrs[index]["@name"]);
   end
   
--   header_tree:add(f_bytes, buffer(0,4));
--   header_tree:add(f_string, buffer(0,4));
--   ptable = DissectorTable.get("udp.port");
--   ptable:add(mcast_port, p_sdn);
   
   print("sdnDisc.dissector completed for packet "..n_sdnDisc_packets)
end

ports_table = DissectorTable.get("udp.port");
--print("Got ports_table which is "..type(ports_table))
--print("got sdnDisc which is "..type(sdnDisc));
--print("Got ports_table:add which is "..type(ports_table:add))
ports_table:add(10002, sdnDisc);
--print("Registered sdnDisc on 10002");

print("SDN loaded - tracking "..n_sdn_topics.." sdn topics")
