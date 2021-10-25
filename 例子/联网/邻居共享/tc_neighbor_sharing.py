#!/usr/bin/python
# Copyright (2021) guanlong huang
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from simulation import Simulation
import sys
from time import sleep
from builtins import input

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
b = BPF(src_file="tc_neighbor_sharing.c", debug=0)

wan_fn = b.load_func("classify_wan", BPF.SCHED_CLS)
pass_fn = b.load_func("pass", BPF.SCHED_CLS)
neighbor_fn = b.load_func("classify_neighbor", BPF.SCHED_CLS)

num_neighbors = 3
num_locals = 2

# class to build the simulation network
class SharedNetSimulation(Simulation):

    def __init__(self, ipdb):
        super(SharedNetSimulation, self).__init__(ipdb)

        # Create the wan namespace, and attach an ingress filter for throttling
        # inbound (download) traffic
        wan_if = self._create_ns("wan0", ipaddr="172.16.1.5/24")[1]
        ipr.tc("add", "ingress", wan_if["index"], "ffff:")
        ipr.tc("add-filter", "bpf", wan_if["index"], ":1", fd=wan_fn.fd,
               prio=1, name=wan_fn.name, parent="ffff:", action="drop",
               classid=1, rate="128kbit", burst=1024 * 32, mtu=16 * 1024)
        ipr.tc("add-filter", "bpf", wan_if["index"], ":2", fd=pass_fn.fd,
               prio=2, name=pass_fn.name, parent="ffff:", action="drop",
               classid=2, rate="1024kbit", burst=1024 * 32, mtu=16 * 1024)
        self.wan_if = wan_if

    # start the namespaces that compose the network, interconnect them with the
    # bridge, and attach the tc filters
    def start(self):
        neighbor_list = []
        local_list = []
        cmd = ["netserver", "-D"]
        for i in range(0, num_neighbors):
            ipaddr = "172.16.1.%d/24" % (i + 100)
            ret = self._create_ns("neighbor%d" % i, ipaddr=ipaddr,
                                  fn=neighbor_fn, cmd=cmd)
            neighbor_list.append(ret)
        for i in range(0, num_locals):
            ipaddr = "172.16.1.%d/24" % (i + 150)
            ret = self._create_ns("local%d" % i, ipaddr=ipaddr,
                                  fn=pass_fn, cmd=cmd)
            local_list.append(ret)

        with ipdb.create(ifname="br100", kind="bridge") as br100:
            for x in neighbor_list:
                br100.add_port(x[1])
            for x in local_list:
                br100.add_port(x[1])
            br100.add_port(self.wan_if)
            br100.up()

try:
    sim = SharedNetSimulation(ipdb)
    sim.start()
    print("Network ready. Create a shell in the wan0 namespace and test with netperf")
    print("   (Neighbors are 172.16.1.100-%d, and LAN clients are 172.16.1.150-%d)"
            % (100 + num_neighbors - 1, 150 + num_locals - 1))
    print(" e.g.: ip netns exec wan0 netperf -H 172.16.1.100 -l 2")
    input("Press enter when finished: ")
finally:
    if "sim" in locals(): sim.release()
    if "br100" in ipdb.interfaces: ipdb.interfaces.br100.remove().commit()
    ipdb.release()


