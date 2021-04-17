#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack

IFNAMSIZ = 16 # uapi/linux/if.h
XT_TABLE_MAXNAMELEN = 32 # uapi/linux/netfilter/x_tables.h

FUNNAMESIZ = 30

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]


def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default

def event_printer(cpu, data, size):
    # Decode event
    event = b["ipt_events"].event(data)

    # Decode address
    saddr = inet_ntop(AF_INET, pack("=I", event.saddr))
    daddr = inet_ntop(AF_INET, pack("=I", event.daddr))


    # Decode flow
    flow = "%s:%d -> %s:%d" % (saddr, event.sport, daddr, event.dport)

    verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNKNOWN~")
    hook = _get(HOOKNAMES, event.hook, "~UNKNOWN~")
    # my x1 carbon has kcp2tun, just ignore
    if event.sport == 3333 or event.dport == 3333:
        return

    # Print event
    print("%-30s [%12s] %-50s %-10s %-15s %-15s" %
          (event.funcname, event.netns, flow, event.tablename, hook, verdict))

if __name__ == "__main__":
    # Build probe and open event buffer
    b = BPF(src_file='tracepkt.c')
    b["ipt_events"].open_perf_buffer(event_printer)

    print("%-30s [%12s] %-50s %-10s %-15s %-15s" % ("TRACEPOINT", 'NETWORK NS', 'ADDRESSES', 'TABLE', 'CHAIN', 'TARGET'))

    # Listen for event until the ping process has exited
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
