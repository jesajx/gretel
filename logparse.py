#!/usr/bin/env python3

import sys
import re
import pathlib

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

nodes = dict()

for path in nginx_log_paths:
    with open(path, "r") as f:
        lines = f.read().splitlines()
        for line in lines:
            if "GRETEL NODE" in line:
                m = re.search(r"GRETEL NODE ([0-9a-z]+(-[0-9a-z]+){3}) gp=(\d+) pid=(\d+) file=(\S+) lineno=(\d+)", line)
                if not m:
                    raise ValueError("bad parse", line)
                name = m.group(1)
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

def explain(node):
    # TODO
    return ""


#edges = {(f'node{a}', f'node{b}') for a,b in edges}
#nodes = {x for a,b in edges for x in [a,b]}

for a,b in edges:
    for x in [a,b]:
        nodes.setdefault(x, dict())


node_attributes = dict()

for n,node_data in nodes.items():
    name = n
    [a,b,c,d] = name.split("-")
    a = GRETEL_A_TYPES.get(int(a,16), str(a))
    name = "-".join([a,b,c,d])
    label = name
    if len(node_data) != 0:
        for k in sorted(node_data.keys()):
            v = node_data[k]
            if k == "filename":
                v = pathlib.Path(v).name
            label += f' {k}={v}'
    node_attributes.setdefault(n, dict())["label"] = label


    gp = node_data.get("gp", None)
    if gp is not None:
        gp = int(gp)
    if gp is not None:
        color = "red"
        if gp == 1048577:
            color = "green"
        elif gp == 1048578:
            color = "blue"

        node_attributes.setdefault(n, dict())["color"] = color


dotfile_put("test.dot", nodes, edges, node_attributes=node_attributes)

