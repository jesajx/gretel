#!/usr/bin/env python3

# eBPF API reference: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

import sys
import ctypes
import os
import time
import re
import bcc
import pathlib


this_script_dir = pathlib.Path(__file__).parent

ctype_u64 = ctypes.c_uint64
ctype_u32 = ctypes.c_uint32

cmdline_cache = dict()
def get_cmdline(pid):
    if pid not in cmdline_cache:
        try:
            with open(f'/proc/{pid}/cmdline') as f:
                cmdline_cache[pid] = f.read()
        except FileNotFoundError:
            return ""
    return cmdline_cache[pid]

c_script_path = this_script_dir / "gretel_bcc.c"
with c_script_path.open("rb") as f:
    progtext = f.read()


def load_syscall_nrs():
    res = dict()
    path = "/usr/include/asm/unistd_64.h"
    with open(path) as f:
        lines = f.readlines()
        for line in lines:
            m = re.search(r'#define __NR_([a-z_0-9]+)\s+(\d+)', line)
            if m:
                name = m.group(1)
                nr = int(m.group(2))
                res[nr] = name
    return res



SYSCALL_NAME_FROM_NR = load_syscall_nrs()

b = bcc.BPF(text=progtext)

execve_fnname = b.get_syscall_fnname("prctl")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__prctl")

SYSCALL_RECV = 1
SYSCALL_SEND = 2
GRETEL_A_TYPES = {
        0: "ERROR",
        1: "SYSCALL_RECV",
        2: "SYSCALL_SEND",
        3: "INODE_READ",
        4: "INODE_WRITE",
        5: "USER",
        6: "BOOT",
        7: "NEW_PID",
}

def hexpad(x, pad=16):
    res = hex(x)
    res = res[2:] # remote "0x"

    if len(res) < pad:
        res = ("0" * (pad-len(res))) + res

    return res

class Gretel(ctypes.Structure):
    _fields_ = [("a", ctype_u64),
                ("b", ctype_u64),
                ("c", ctype_u64),
                ("d", ctype_u64)]

    def to_hard(self):
        res = "-".join(hexpad(x) for x in [self.a, self.b, self.c, self.d])
        return res


    def to_human_tuple(self):
        a = GRETEL_A_TYPES.get(self.a, hexpad(self.a))
        return a + "-" + ("-".join(hexpad(x) for x in [self.b, self.c, self.d]))

    __str__ = to_human_tuple


LGRETEL_TYP_ERROR = 0
LGRETEL_TYP_NODE = 1
LGRETEL_TYP_LINK = 2



class LGretelNode(ctypes.Structure):
    _fields_ = [("event_id", Gretel),
                ("lineno", ctype_u32)]

    def to_hard(self):
        return f'{self.event_id.to_hard()}, gretel_bcc.c:{self.lineno}'

    def to_human_tuple(self):
        return (self.event_id.to_human_tuple(), self.lineno) # TODO

class LGretelLink(ctypes.Structure):
    _fields_ = [("parent_event_id", Gretel),
                ("event_id", Gretel)]

    def to_hard(self): # TODO maybe __str__?
        return f'{self.parent_event_id.to_hard()}->{self.event_id.to_hard()}'

    def to_human_tuple(self):
        return (self.parent_event_id.to_human_tuple(), self.event_id.to_human_tuple())

class LGretelUnion(ctypes.Union):
    _fields_ = [("link", LGretelLink),
                ("node", LGretelNode)]

class LGretelLogEntry(ctypes.Structure):
    _fields_ = [
                ("typ", ctype_u32),
                ("u", LGretelUnion),
                ("pad", ctype_u32),
                ]

    def to_hard(self):
        if self.typ == LGRETEL_TYP_NODE:
            return self.u.node.to_hard()
        elif self.typ == LGRETEL_TYP_LINK:
            return self.u.link.to_hard()
        else:
            return f'LGretelLogEntry({self.typ})'

    def to_human_tuple(self):
        if self.typ == LGRETEL_TYP_NODE:
            return self.u.node.to_human_tuple()
        elif self.typ == LGRETEL_TYP_LINK:
            return self.u.link.to_human_tuple()
        else:
            return ('LGretelLogEntry', self.typ)

MY_PID = os.getpid()


with open("gretel_bcc.log", "w") as ff:
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(LGretelLogEntry)).contents

        if event.typ == LGRETEL_TYP_NODE:
            print("node", event.to_human_tuple())
            print(event.to_hard(), file=ff)
        elif event.typ == LGRETEL_TYP_LINK:
            print("link", event.to_human_tuple())
            print(event.to_hard(), file=ff)
        else:
            print("bad event") # TODO

    b["events"].open_perf_buffer(print_event) # TODO maybe just queue events in callback

    print("---RECORDING---")

    last_flush = time.time()

    while 1:
        try:
            b.perf_buffer_poll(0)
            time.sleep(0.01)
            if time.time() - last_flush > 1:
                ff.flush()
                last_flush = time.time()
        except KeyboardInterrupt:
            print("interrupt")
            exit()
