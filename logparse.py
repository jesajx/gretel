#!/usr/bin/env python3

import sys
import re

nginx_log_paths = [
    "nginx1.logs/error.log",
    "nginx2.logs/error.log",
]
ebpf_log_path = "gretel_bcc.log"


edges = set()

nodes = dict()

for path in nginx_log_paths:
    with open(path, "r") as f:
        lines = f.read().splitlines()
        for line in lines:
            if "GRETEL NODE" in line:
                m = re.search(r"GRETEL NODE ([0-9a-z]+(-[0-9a-z]+){3}) gp=(\d+) pid=(\d+) file=(\S+) lineno=(\d+)", line)
                if not m:
                    raise ValueError("bad parse", line)
                name = m.group(1).replace("-", "")
                nodes[name] = {
                    "gp": m.group(3),
                    "pid": m.group(4),
                    "filename": m.group(5),
                    "lineno": m.group(6),
                }
            elif "GRETEL LINK" in line:
                m = re.search(r"GRETEL LINK ([0-9a-z]+(-[0-9a-z]+){3})->([0-9a-z]+(-[0-9a-z]+){3})", line)
                if not m:
                    raise ValueError("bad parse", line)
                pred = m.group(1).replace("-", "")
                succ = m.group(3).replace("-", "")
                #print(pred, "->", succ)

                edges.add((pred, succ))


with open(ebpf_log_path, "r") as f:
    lines = f.read().splitlines()
    for line in lines:
        if len(line) == 0:
            continue
        m = re.search("([0-9a-z]+(-[0-9a-z]+){3})->([0-9a-z]+(-[0-9a-z]+){3})", line)
        if not m:
            raise ValueError("bad parse", line)
        pred = m.group(1).replace("-", "")
        succ = m.group(3).replace("-", "")
        #print(pred, "->", succ)

        edges.add((pred, succ))

# TODO replace
# from TODO import dotfile_put
#GRETEL_A_TYPES = {
#        0: "ERROR",
#        1: "SYSCALL_RECV",
#        2: "SYSCALL_SEND",
#        3: "INODE_READ",
#        4: "INODE_WRITE",
#        5: "USER",
#        6: "BOOT",
#        7: "NEW_PID",
#        }
#
#def explain(node):
#    # TODO
#    return ""
#
#
##edges = {(f'node{a}', f'node{b}') for a,b in edges}
##nodes = {x for a,b in edges for x in [a,b]}
#
#for a,b in edges:
#    for x in [a,b]:
#        nodes.setdefault(x, dict())
#
#
#node_attributes = dict()
#
#for n,d in nodes.items():
#    label = n
#    if len(d) != 0:
#        label = f'{n} (gp={d["gp"]} pid={d["pid"]} f={pathlib.Path(d["filename"]).name}:{d["lineno"]})'
#
#    node_attributes.setdefault(n, dict())["label"] = label
#
#dotfile_put("test.dot", nodes, edges, node_attributes=node_attributes)

