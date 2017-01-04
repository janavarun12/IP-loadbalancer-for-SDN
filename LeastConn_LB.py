# Copyright 2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A very sloppy IP load balancer.

Run it with --ip=<Service IP> --servers=IP1,IP2,...

Please submit improvements. :)
"""

from pox.core import core
import pox
log = core.getLogger("iplb")

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr, parse_cidr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from pox.openflow.of_json import *
from pox.lib.revent import EventContinue, EventHalt
import pox.openflow.libopenflow_01 as of

import time
import random

FLOW_IDLE_TIMEOUT = 10
FLOW_MEMORY_TIMEOUT = 60 * 5

port_bytes = dict() #Tx, portno
switch_stat = dict() #switchID, port_bytes (Tx,portno)
min_load = list() #switchID, min_portno
connections_per_server = dict ()

connections_per_server[IPAddr('10.0.0.1')]=0
connections_per_server[IPAddr('10.0.0.2')]=0
connections_per_server[IPAddr('10.0.0.3')]=0

class MemoryEntry (object):
  """
  Record for flows we are balancing

  Table entries in the switch "remember" flows for a period of time, but
  rather than set their expirations to some long value (potentially leading
  to lots of rules for dead connections), we let them expire from the
  switch relatively quickly and remember them here in the controller for
  longer.

  Another tactic would be to increase the timeouts on the switch and use
  the Nicira extension which can match packets with FIN set to remove them
  when the connection closes.
  """
  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport


class iplb (object):
  """
  A simple IP load balancer

  Give it a service_ip and a list of server IP addresses.  New TCP flows
  to service_ip will be randomly redirected to one of the servers.

  We probe the servers to see if they're alive by sending them ARPs.
  """
  def __init__ (self, connection, service_ip, servers = []):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.con = connection
    self.mac = self.con.eth_addr
    self.live_servers = {} # IP -> MAC,port
    self.port_ip_map={1:IPAddr('10.0.0.1'),2:IPAddr('10.0.0.2'),3:IPAddr('10.0.0.3')} #port->IP

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log

    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = 5

    # How long do we wait for an ARP reply before we consider a server dead?
    self.arp_timeout = 3

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)

  def _do_expire (self):
    """
    Expire probes and "memorized" flows

    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r

  def _pick_server (self, key, inport):
    """
    Pick a server for a (hopefully) new connection
    """
    print(connections_per_server.values())
##    for i in connections_per_server.values():
##      if i is not 0:
##        all_zero=False
##      else:
##        all_zero=True
    if(connections_per_server.values()==[0,0,0]):
      all_zero=True
    else:
      all_zero=False
    if(all_zero):
      print("first conn. random")
      return random.choice(self.live_servers.keys())
    else:
      for i in range(1,4):
        str_f="pox/ext/ConnectionCounters/counter_10.0.0."+str(i)+".txt"
        f_obj=open(str_f,'r')
        print('reading counter_10.0.0.',i)
        active_conn_flag=f_obj.read()
        print('active connection flag is',active_conn_flag)
        f_obj.close()
        if(int(active_conn_flag) is 0):
          print(connections_per_server[IPAddr('10.0.0.'+str(i))])
          if connections_per_server[IPAddr('10.0.0.'+str(i))] is not 0 :
            connections_per_server[IPAddr('10.0.0.'+str(i))]-=1
            print("decrementing counter for ",IPAddr('10.0.0.'+str(i)))
        else:
          print("Connection already accounted for.No change to be made")
        
      print(connections_per_server)
      min_server=min(connections_per_server, key=connections_per_server.get)
      print('The server with least connections: ',min_server)
      return (min_server)
        
      


  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed

    global connections_per_server

    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.log.info("Server %s up", arpp.protosrc)
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()

    # It's TCP.
    
    ipp = packet.find('ipv4')

    if ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.debug("No client for %s", key)
        return drop()

      # Refresh time timeout and reinstall.
      entry.refresh()

      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      # Ah, it's for our service IP and needs to be load balanced

      # Do we already know this flow?
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        # Don't know it (hopefully it's new!)
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        # Pick a server for this flow
        server = self._pick_server(key, inport)
        self.log.debug("Directing traffic to %s", server)
        
        if server in connections_per_server:
          connections_per_server[server] += 1
          conn_counter = open('pox/ext/ConnectionCounters/counter_'+str(server)+'.txt', 'w')
          conn_counter.write('1')
          print("connection active")
          conn_counter.close()
        else:
          connections_per_server[server] = 1
          
        print(connections_per_server)

        
        
        
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry
   
      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


# Remember which DPID we're operating on (first one to connect)
_dpid = None
def _timer_func():
        #print 'timer function'
        #print core.openflow._connections.values()
        core.openflow.addListenerByName("PortStatsReceived",_handle_portstats_received)
        for connection in core.openflow._connections.values():
            connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))


def _handle_portstats_received(event):
      global port_bytes
      global min_load
      global switch_stat
      switchid_str = dpidToStr(event.dpid)
      switchid_int = switchid_str[-1]
      switchID = int(switchid_int)
      #print("EVENTS STATS ARE:",event.stats)
      
      if (switchID == 1):
          for f in event.stats:
              #print(f.port_no)
              if int(f.port_no)<4:
                  if int(f.port_no) in port_bytes:
                    port_bytes[int(f.port_no)] += f.tx_bytes
                  else:
                      #print(dir(f),f.port_no)
                      port_bytes[int(f.port_no)] = f.tx_bytes

      switch_stat[switchID] = port_bytes
      min_port = min(port_bytes, key=port_bytes.get)

      #print("MIN_PORT IS: ",min_port)
      min_load.insert(0, switchID)
      min_load.insert(1, min_port)
      #print min_load

def launch (ip, servers):
  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
  ip = IPAddr(ip)

  # Boot up ARP Responder
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})
  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      log.info("IP Load Balancer Ready.")
      Timer(1, _timer_func, recurring = True)
      core.registerNew(iplb, event.connection, IPAddr(ip), servers)
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)


  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
