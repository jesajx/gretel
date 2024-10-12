#!/usr/bin/env python3

import sys
import re
import pathlib

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

def dotfile_put(path, *args, **kwargs):
    it = gen_dotfile(*args, **kwargs)
    with open(path, "w") as f:
        for s in it:
            f.write(s)

def gen_dotfile(node_list, edge_list, graph_attributes=None, node_attributes=None, edge_attributes=None, is_directed_graph=True): # TODO
    if graph_attributes == None:
        graph_attributes = dict()
    if node_attributes == None:
        node_attributes = dict()
    if edge_attributes == None:
        edge_attributes = dict()

    if len(node_list) != len(set(node_list)):
        raise Exception("TODO duplicate nodes", {x for x,c in histo_count(node_list).items() if c >= 2})

    if len(edge_list) != len(set(edge_list)):
        raise Exception("TODO duplicate edges")

    if len(node_attributes.keys() - set(node_list)) != 0:
        raise Exception("TODO")
    if len(edge_attributes.keys() - set(edge_list)) != 0:
        raise Exception("TODO")

    keywords = ["graph", "node", "edge"]
    for k in keywords:
        if k in node_list:
            raise Exception("TODO")

    if is_directed_graph:
        yield "digraph"
    else:
        yield "graph"

    yield " {\n"

    def gen_single_attribute(k, v):
        k = str(k).replace('"', '\\"')

        yield '"'
        if k == "htmllabel":
            yield "label"
        else:
            yield k
        yield '"'
        yield '='
        if k == "htmllabel":
            yield '<'
            yield v
            yield '>'
        else:
            yield '"'
            yield str(v).replace('"', '\\"')
            yield '"'
    def gen_attributes(attributes_dict):
        if len(attributes_dict) != 0:
            if "htmllabel" in attributes_dict and "label" in attributes_dict:
                raise Exception("TODO")

            yield "["

            first = True
            for k,v in attributes_dict.items():
                if not first:
                    yield ', '
                yield from gen_single_attribute(k, v)
                first = False

            yield "]"


    for k,v in graph_attributes.items():
        yield from gen_single_attribute(k, v)
        yield ";\n"

    def escape_name(name):
        yield '"'
        yield name.replace('\\', '\\\\')
        yield name.replace('"', '\\"')
        yield '"'

    for node in node_list:
        attr = dict()
        if node in node_attributes:
            attr = node_attributes[node]

        yield from escape_name(node)

        if len(attr) != 0:
            yield ' '
            yield from gen_attributes(attr)
        yield ';\n'

    for a,b in edge_list:
        attr = dict()

        if (a,b) in edge_attributes:
            attr.update(edge_attributes[(a,b)])
        if not is_directed_graph and (b,a) in edge_attributes:
            attr.update(edge_attributes[(b,a)])

        yield from escape_name(a)
        yield ('->' if is_directed_graph else '--')
        yield from escape_name(b)

        if len(edge_attributes) != 0:
            yield ' '
            yield from gen_attributes(attr)
        yield ';\n'

    yield "}\n"

nginx_log_paths = [
    "nginx1.logs/error.log",
    "nginx2.logs/error.log",
]
ebpf_log_path = "gretel_bcc.log"


edges = set()

edges.add( # TODO from curl
('0000000000000005-75f715620f8529bc-735c6476008ca162-227fad7b5e376987', '0000000000000005-0000000000001234-0000000000001234-0000000022221234', )
)

nodes = dict()

for path in nginx_log_paths:
    with open(path, "r") as f:
        lines = f.read().splitlines()
        for line in lines:
            if "GRETEL NODE" in line:
                m = re.search(r"GRETEL NODE ([0-9a-z]+(-[0-9a-z]+){3}) (gp=(\d+) pid=(\d+) file=(\S+) lineno=(\d+).*)", line)
                if not m:
                    raise ValueError("bad parse", line)
                name = m.group(1)
                new_data = {
                    "s": m.group(3),
                    "gp": int(m.group(4)),
                    "pid": m.group(5),
                    "filename": m.group(6),
                    "lineno": m.group(7),
                }
                if name in nodes:
                    raise ValueError("TODO", name, nodes[name], new_data)
                nodes[name] = new_data
            elif "GRETEL LINK" in line:
                m = re.search(r"GRETEL LINK ([0-9a-z]+(-[0-9a-z]+){3})->([0-9a-z]+(-[0-9a-z]+){3})", line)
                if not m:
                    raise ValueError("bad parse", line)
                pred = m.group(1)
                succ = m.group(3)
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
        pred = m.group(1)
        succ = m.group(3)
        #print(pred, "->", succ)

        edges.add((pred, succ))

GRETEL_A_TYPES_NAME_FROM_INT = {
        0: "ERROR",
        1: "SYSCALL_RECV",
        2: "SYSCALL_SEND",
        3: "INODE_READ",
        4: "INODE_WRITE",
        5: "USER",
        6: "BOOT",
        7: "NEW_PID",
        }

GRETEL_A_TYPES_INT_FROM_NAME = {k:i for i,k in GRETEL_A_TYPES_NAME_FROM_INT.items()}

def explain(node):
    # TODO
    return ""


#edges = {(f'node{a}', f'node{b}') for a,b in edges}
#nodes = {x for a,b in edges for x in [a,b]}

for a,b in edges:
    for x in [a,b]:
        nodes.setdefault(x, dict())

gp_nginx1 = 0x100001
gp_nginx2 = 0x100002

node_attributes = dict()

for n,node_data in nodes.items():
    name = n
    [a_str,b_str,c_str,d_str] = name.split("-")
    a_int = int(a_str, 16)
    b_int = int(b_str, 16)
    c_int = int(c_str, 16)
    d_int = int(d_str, 16)

    name_a = GRETEL_A_TYPES_NAME_FROM_INT.get(a_int, a_str)

    name_b = b_str

    name_c = c_str

    if GRETEL_A_TYPES_NAME_FROM_INT[a_int] == "SYSCALL_RECV":
        name_c = SYSCALL_NAME_FROM_NR[c_int]

    name_d = d_str


    name = "-".join([name_a, name_b, name_c, name_d])
    label = name
    if len(node_data) != 0:
        for k in sorted(node_data.keys()):
            v = node_data[k]
            if k == "filename":
                v = pathlib.Path(v).name
            if k == "gp":
                if v == gp_nginx1:
                    v = "nginx1"
                elif v == gp_nginx2:
                    v = "nginx2"
            label += f' {k}={v}'
    node_attributes.setdefault(n, dict())["label"] = label

    color = "red"

    gp = node_data.get("gp", None)
    if gp is not None:
        gp = int(gp)
    if gp is not None:
        if gp == gp_nginx1:
            color = "blue"
        elif gp == gp_nginx2:
            color = "green"
    elif (a_int,b_int,c_int) == (5,0x1234,0x1234):
        color = "magenta"

    node_attributes.setdefault(n, dict())["color"] = color


dotfile_put("test.dot", nodes, edges, node_attributes=node_attributes)

