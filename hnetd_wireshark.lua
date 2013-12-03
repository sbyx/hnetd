-- -*-lua-*-
--
-- $Id: hnetd_wireshark.lua $
--
-- Author: Markus Stenberg <mstenber@cisco.com>
--
-- Copyright (c) 2013 cisco Systems, Inc.
--
-- Created:       Tue Dec  3 11:13:05 2013 mstenber
-- Last modified: Tue Dec  3 13:08:14 2013 mstenber
-- Edit time:     78 min
--

-- This is Lua module which provides VERY basic dissector for TLVs we
-- transmit.

-- Usage: wireshark -X lua_script:hnetd_wireshark.lua

p_hcp = Proto("hcp", "Homenet Control Protocol")

local f_id = ProtoField.uint16('hcp.id', 'TLV id')
local f_len = ProtoField.uint16('hcp.len', 'TLV len')
local f_data = ProtoField.bytes('hcp.data', 'TLV data', base.HEX)

local f_nid_hash = ProtoField.bytes('hcp.node_identifier_hash', 
                                    'Node identifier', base.HEX)
local f_data_hash = ProtoField.bytes('hcp.data_hash',
                                     'Node data hash', base.HEX)
local f_network_hash = ProtoField.bytes('hcp.network_hash',
                                        'Network state hash', base.HEX)

local f_lid = ProtoField.uint32('hcp.llid', 'Local link identifier')
local f_rlid = ProtoField.uint32('hcp.rlid', 'Remote link identifier')
local f_upd = ProtoField.uint32('hcp.update_number', 'Update number')
local f_ms = ProtoField.uint32('hcp.ms_since_origination', 
                               'Time since origination (ms)')

p_hcp.fields = {f_id, f_len, f_data,
                f_nid_hash, f_data_hash, f_network_hash,
                f_lid, f_rlid, f_upd, f_ms}

local tlvs = {
   [1]={name='link-id', 
        contents={{16, f_nid_hash},
                  {4, f_lid}},
   },
   [2]={name='req-net-hash'},
   [3]={name='req-node-hash',
        contents={{16, f_nid_hash}},
   },
   [4]={name='node-state',
        contents={{16, f_nid_hash},
                  {4, f_upd},
                  {4, f_ms},
                  {16, f_data_hash},
        }
   },
   [5]={name='network-hash',
        contents={{16, f_network_hash}}},
   [6]={name='node-data', 
        contents={{16, f_nid_hash},
                  {4, f_upd}},
        recurse=true},
   [7]={name='.. key'},
   [8]={name='.. neighbor', contents={{16, f_nid_hash,
                                       4, f_rlid,
                                       4, f_lid}},
   },
}

function p_hcp.dissector(buffer, pinfo, tree)
   pinfo.cols.protocol = 'hcp'
   function rec_decode(ofs, left, tree)
      while left >= 4 
      do
         local partial
         local rid = buffer(ofs, 2)
         local rlen = buffer(ofs+2, 2)
         local id = rid:uint()
         local len = rlen:uint() 
         local bs = ''
         local ps = ''
         local tlv = tlvs[id] or {}
         if tlv.name
         then
            bs = ' (' .. tlv.name .. ')'
         end
         if len < 4
         then
            ps = ' (broken - len<4)'
            partial = true
         end
         if len > left
         then
            len = left
            ps = ' (partial)'
            partial = true
         end
         local tree2 = tree:add(buffer(ofs, len), 
                                string.format('TLV %d%s - %d data bytes%s',
                                              id, bs, len, ps))
         if partial
         then
            return
         end
         local fid = tree2:add(f_id, rid)
         fid:append_text(bs)
         local flen = tree2:add(f_len, rlen)
         if len > 4 
         then
            local fdata = tree2:add(f_data, buffer(ofs + 4, len - 4))
            if tlv.contents
            then
               local cofs = ofs + 4
               local clen = len - 4
               for i, v in ipairs(tlv.contents)
               do
                  local elen, ef = unpack(v)
                  if elen > clen
                  then
                     return
                  end
                  fdata:add(ef, buffer(cofs, elen))
                  clen = clen - elen
                  cofs = cofs + elen
               end
               if tlv.recurse 
               then
                  rec_decode(cofs, clen, fdata)
               end
            end
         end
         left = left - len
         ofs = ofs + len
      end
   end
   rec_decode(0, buffer:len(), tree:add(p_hcp, buffer()))
end

-- register as udp dissector
udp_table = DissectorTable.get("udp.port")
udp_table:add(8808, p_hcp)
udp_table:add(38808, p_hcp)
