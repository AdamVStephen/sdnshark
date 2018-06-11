# sdnshark
Wireshark plugin for ITER SDN protocols.

The plugin consists of two protocol dissectors.  The first is bound to port 10002 which is the SDN discovery channel.  As packets arrive on that port, the xml embedded message format is parsed, and the simpler SDN dissector is registered for each port/topic.

# Status
Beta version - needs further refinement to be more efficient and to fill out the secondary SDN dissector.   A future version should also have a Lua listener so that multicast membership can be asserted in the absence of local subscribers.

# Dependencies
Lua-Simple-XML-Parser Lua library - managed as a related github project submodule.   Need to set LUA_PATH prior to starting Wireshark

# Installation
1. Ensure SimpleXML  Lua submodule checked out and LUA_PATH set appropriately. 
2. Copy sdn.lua to your $HOME/.config/wireshark/plugins directory and hit Ctrl-Shift-L to reload Lua plugins.


# References
https://github.com/Cluain/Lua-Simple-XML-Parser

See also WireBait as a nice project for unit testing wireshark lua code outside of wireshark.

