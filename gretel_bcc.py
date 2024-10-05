#!/usr/bin/env python3

# eBPF API reference: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

import ctypes
import os
import time
import re
import bcc

cmdline_cache = dict()
def get_cmdline(pid):
    if pid not in cmdline_cache:
        try:
            with open(f'/proc/{pid}/cmdline') as f:
                cmdline_cache[pid] = f.read()
        except FileNotFoundError:
            return ""
    return cmdline_cache[pid]

with open("gretel_bcc.c", "rb") as f:
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

class BigEventId(ctypes.Structure):
    _fields_ = [("a", ctypes.c_ulonglong),
                ("b", ctypes.c_ulonglong),
                ("c", ctypes.c_ulonglong),
                ("d", ctypes.c_ulonglong)]

    def getpid(self):
        if self.a == 1:
            return self.b & 0xFFFFFFFF
        return None

    def to_hard(self):
        res = "-".join(hexpad(x) for x in [self.a, self.b, self.c, self.d])
        return res


    def to_human_tuple(self):
        a = self.a
        b = self.b
        c = self.c
        d = self.d
        if self.a in [SYSCALL_RECV, SYSCALL_SEND]:
            pid = self.b & 0xFFFFFFFF
            tgid = self.b >> 32
            cmdline = get_cmdline(pid)
            b = {"pid": pid, "cmd": cmdline}
            if tgid != pid:
                b["tgid"] = tgid

            c = SYSCALL_NAME_FROM_NR.get(c, c)

        if a in GRETEL_A_TYPES:
            a = GRETEL_A_TYPES[self.a]

        return (a, b, c, d)


class OutData(ctypes.Structure):
    _fields_ = [("parent_event_id", BigEventId),
                ("event_id", BigEventId),]


    def to_hard(self):
        return f'{self.parent_event_id.to_hard()}->{self.event_id.to_hard()}'

    def to_human_tuple(self):
        return (self.parent_event_id.to_human_tuple(), self.event_id.to_human_tuple())

MY_PID = os.getpid()


with open("gretel_bcc.log", "w") as ff:
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(OutData)).contents
        #event = b["events"].event(data)
        #print(f'tsk={event.pid_tgid} err={event.err} nsys={event.nsys} event_type={event.event_type_id}, event_id={event.event_id}')

        if False:
            pids = {event.parent_event_id.getpid(), event.event_id.getpid()}
            pids.discard(None)

            if MY_PID in pids:
                return
            for pid in pids:
                cmdline = get_cmdline(pid)
                if "sudo" in cmdline or "sshd" in cmdline:
                    return


        print(event.to_human_tuple())
        print(event.to_hard(), file=ff)

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
