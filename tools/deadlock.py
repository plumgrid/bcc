#!/usr/bin/env python
#
# deadlock  Detects potential deadlocks (lock order inversions)
#           on a running process. For Linux, uses BCC, eBPF.
#
# USAGE: deadlock.py [-h] [--binary BINARY] [--dump-graph DUMP_GRAPH]
#                    [--verbose] [--lock-symbols LOCK_SYMBOLS]
#                    [--unlock-symbols UNLOCK_SYMBOLS]
#                    pid
#
# This traces pthread mutex lock and unlock calls to build a directed graph
# representing the mutex wait graph:
#
# - Nodes in the graph represent mutexes.
# - Edge (A, B) exists if there exists some thread T where lock(A) was called
#   and lock(B) was called before unlock(A) was called.
#
# If the program finds a potential lock order inversion, the program will dump
# the cycle of mutexes and the stack traces where each mutex was acquired, and
# then exit.
#
# This program can only find potential deadlocks that occur while the program
# is tracing the process. It cannot find deadlocks that may have occurred
# before the program was attached to the process.
#
# Since this traces all mutex lock and unlock events and all thread creation
# events on the traced process, the overhead of this bpf program can be very
# high if the process has many threads and mutexes. You should only run this on
# a process where the slowdown is acceptable.
#
# Note: This tool does not work for shared mutexes or recursive mutexes.
#
# For shared (read-write) mutexes, a deadlock requires a cycle in the wait
# graph where at least one of the mutexes in the cycle is acquiring exclusive
# (write) ownership.
#
# For recursive mutexes, lock() is called multiple times on the same mutex.
# However, there is no way to determine if a mutex is a recursive mutex
# after the mutex has been created. As a result, this tool will not find
# potential deadlocks that involve only one mutex.
#
# Copyright 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 01-Feb-2017   Kenny Yu   Created this.

from __future__ import (
    absolute_import, division, unicode_literals, print_function
)
from bcc import BPF
from collections import defaultdict
import argparse
import json
import os
import subprocess
import sys
import time


CWD = os.path.dirname(os.path.realpath(__file__))


class DiGraph(object):
    '''
    Adapted from networkx: http://networkx.github.io/
    Represents a directed graph. Edges can store (key, value) attributes.
    '''

    def __init__(self):
        # Map of node -> set of nodes
        self.adjacency_map = {}
        # Map of (node1, node2) -> map string -> arbitrary attribute
        # This will not be copied in subgraph()
        self.attributes_map = {}

    def neighbors(self, node):
        return self.adjacency_map.get(node, set())

    def edges(self):
        edges = []
        for node, neighbors in self.adjacency_map.items():
            for neighbor in neighbors:
                edges.append((node, neighbor))
        return edges

    def nodes(self):
        return self.adjacency_map.keys()

    def attributes(self, node1, node2):
        return self.attributes_map[(node1, node2)]

    def add_edge(self, node1, node2, **kwargs):
        if node1 not in self.adjacency_map:
            self.adjacency_map[node1] = set()
        if node2 not in self.adjacency_map:
            self.adjacency_map[node2] = set()
        self.adjacency_map[node1].add(node2)
        self.attributes_map[(node1, node2)] = kwargs

    def remove_node(self, node):
        self.adjacency_map.pop(node, None)
        for _, neighbors in self.adjacency_map.items():
            neighbors.discard(node)

    def subgraph(self, nodes):
        graph = DiGraph()
        for node in nodes:
            for neighbor in self.neighbors(node):
                if neighbor in nodes:
                    graph.add_edge(node, neighbor)
        return graph

    def node_link_data(self):
        '''
        Returns the graph as a dictionary in a format that can be
        serialized.
        '''
        data = {
            'directed': True,
            'multigraph': False,
            'graph': {},
            'links': [],
            'nodes': [],
        }

        # Do one pass to build a map of node -> position in nodes
        node_to_number = {}
        for node in self.adjacency_map.keys():
            node_to_number[node] = len(data['nodes'])
            data['nodes'].append({'id': node})

        # Do another pass to build the link information
        for node, neighbors in self.adjacency_map.items():
            for neighbor in neighbors:
                link = self.attributes_map[(node, neighbor)].copy()
                link['source'] = node_to_number[node]
                link['target'] = node_to_number[neighbor]
                data['links'].append(link)
        return data


def strongly_connected_components(G):
    '''
    Adapted from networkx: http://networkx.github.io/
    Parameters
    ----------
    G : DiGraph
    Returns
    -------
    comp : generator of sets
        A generator of sets of nodes, one for each strongly connected
        component of G.
    '''
    preorder = {}
    lowlink = {}
    scc_found = {}
    scc_queue = []
    i = 0  # Preorder counter
    for source in G.nodes():
        if source not in scc_found:
            queue = [source]
            while queue:
                v = queue[-1]
                if v not in preorder:
                    i = i + 1
                    preorder[v] = i
                done = 1
                v_nbrs = G.neighbors(v)
                for w in v_nbrs:
                    if w not in preorder:
                        queue.append(w)
                        done = 0
                        break
                if done == 1:
                    lowlink[v] = preorder[v]
                    for w in v_nbrs:
                        if w not in scc_found:
                            if preorder[w] > preorder[v]:
                                lowlink[v] = min([lowlink[v], lowlink[w]])
                            else:
                                lowlink[v] = min([lowlink[v], preorder[w]])
                    queue.pop()
                    if lowlink[v] == preorder[v]:
                        scc_found[v] = True
                        scc = {v}
                        while (
                            scc_queue and preorder[scc_queue[-1]] > preorder[v]
                        ):
                            k = scc_queue.pop()
                            scc_found[k] = True
                            scc.add(k)
                        yield scc
                    else:
                        scc_queue.append(v)


def simple_cycles(G):
    '''
    Adapted from networkx: http://networkx.github.io/
    Parameters
    ----------
    G : DiGraph
    Returns
    -------
    cycle_generator: generator
       A generator that produces elementary cycles of the graph.
       Each cycle is represented by a list of nodes along the cycle.
    '''

    def _unblock(thisnode, blocked, B):
        stack = set([thisnode])
        while stack:
            node = stack.pop()
            if node in blocked:
                blocked.remove(node)
                stack.update(B[node])
                B[node].clear()

    # Johnson's algorithm requires some ordering of the nodes.
    # We assign the arbitrary ordering given by the strongly connected comps
    # There is no need to track the ordering as each node removed as processed.
    # save the actual graph so we can mutate it here
    # We only take the edges because we do not want to
    # copy edge and node attributes here.
    subG = G.subgraph(G.nodes())
    sccs = list(strongly_connected_components(subG))
    while sccs:
        scc = sccs.pop()
        # order of scc determines ordering of nodes
        startnode = scc.pop()
        # Processing node runs 'circuit' routine from recursive version
        path = [startnode]
        blocked = set()  # vertex: blocked from search?
        closed = set()  # nodes involved in a cycle
        blocked.add(startnode)
        B = defaultdict(set)  # graph portions that yield no elementary circuit
        stack = [(startnode, list(subG.neighbors(startnode)))]
        while stack:
            thisnode, nbrs = stack[-1]
            if nbrs:
                nextnode = nbrs.pop()
                if nextnode == startnode:
                    yield path[:]
                    closed.update(path)
                elif nextnode not in blocked:
                    path.append(nextnode)
                    stack.append((nextnode, list(subG.neighbors(nextnode))))
                    closed.discard(nextnode)
                    blocked.add(nextnode)
                    continue
            # done with nextnode... look for more neighbors
            if not nbrs:  # no more nbrs
                if thisnode in closed:
                    _unblock(thisnode, blocked, B)
                else:
                    for nbr in subG.neighbors(thisnode):
                        if thisnode not in B[nbr]:
                            B[nbr].add(thisnode)
                stack.pop()
                path.pop()
        # done processing this node
        subG.remove_node(startnode)
        H = subG.subgraph(scc)  # make smaller to avoid work in SCC routine
        sccs.extend(list(strongly_connected_components(H)))


def find_cycle(graph):
    '''
    Looks for a cycle in the graph. If found, returns the first cycle.
    If nodes a1, a2, ..., an are in a cycle, then this returns:
        [(a1,a2), (a2,a3), ... (an-1,an), (an, a1)]
    Otherwise returns an empty list.
    '''
    cycles = list(simple_cycles(graph))
    if cycles:
        nodes = cycles[0]
        nodes.append(nodes[0])
        edges = []
        prev = nodes[0]
        for node in nodes[1:]:
            edges.append((prev, node))
            prev = node
        return edges
    else:
        return []


def print_cycle(binary, graph, edges, thread_info, print_stack_trace_fn):
    '''
    Prints the cycle in the mutex graph in the following format:

    Potential Deadlock Detected!

    Cycle in lock order graph: M0 => M1 => M2 => M0

    for (m, n) in cycle:
        Mutex n acquired here while holding Mutex m in thread T:
            [ stack trace ]

        Mutex m previously acquired by thread T here:
            [ stack trace ]

    for T in all threads:
        Thread T was created here:
            [ stack trace ]
    '''

    # List of mutexes in the cycle, first and last repeated
    nodes_in_order = []
    # Map mutex address -> readable alias
    node_addr_to_name = {}
    for counter, (m, n) in enumerate(edges):
        nodes_in_order.append(m)
        # For global or static variables, try to symbolize the mutex address.
        symbol = symbolize_with_objdump(binary, m)
        if symbol:
            symbol += ' '
        node_addr_to_name[m] = 'Mutex M%d (%s0x%016x)' % (counter, symbol, m)
    nodes_in_order.append(nodes_in_order[0])

    print('----------------\nPotential Deadlock Detected!\n')
    print(
        'Cycle in lock order graph: %s\n' %
        (' => '.join([node_addr_to_name[n] for n in nodes_in_order]))
    )

    # Set of threads involved in the lock inversion
    thread_pids = set()

    # For each edge in the cycle, print where the two mutexes were held
    for (m, n) in edges:
        thread_pid = graph.attributes(m, n)['thread_pid']
        thread_comm = graph.attributes(m, n)['thread_comm']
        first_mutex_stack_id = graph.attributes(m, n)['first_mutex_stack_id']
        second_mutex_stack_id = graph.attributes(m, n)['second_mutex_stack_id']
        thread_pids.add(thread_pid)
        print(
            '%s acquired here while holding %s in Thread %d (%s):' % (
                node_addr_to_name[n], node_addr_to_name[m], thread_pid,
                thread_comm
            )
        )
        print_stack_trace_fn(second_mutex_stack_id)
        print('')
        print(
            '%s previously acquired by the same Thread %d (%s) here:' %
            (node_addr_to_name[m], thread_pid, thread_comm)
        )
        print_stack_trace_fn(first_mutex_stack_id)
        print('')

    # Print where the threads were created, if available
    for thread_pid in thread_pids:
        parent_pid, stack_id, parent_comm = thread_info.get(
            thread_pid, (None, None, None)
        )
        if parent_pid:
            print(
                'Thread %d created by Thread %d (%s) here: ' %
                (thread_pid, parent_pid, parent_comm)
            )
            print_stack_trace_fn(stack_id)
        else:
            print(
                'Could not find stack trace where Thread %d was created' %
                thread_pid
            )
        print('')


def symbolize_with_objdump(binary, addr):
    '''
    Searches the binary for the address using objdump. Returns the symbol if
    it is found, otherwise returns empty string.
    '''
    try:
        command = (
            'objdump -tT %s | grep %x | awk {\'print $NF\'} | c++filt' %
            (binary, addr)
        )
        output = subprocess.check_output(command, shell=True)
        return output.decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return ''


def strlist(s):
    '''Given a comma-separated string, returns a list of substrings'''
    return s.strip().split(',')


def main():
    examples = '''Examples:
    deadlock 181                 # Analyze PID 181

    deadlock 181 --binary /lib/x86_64-linux-gnu/libpthread.so.0
                                 # Analyze PID 181 and locks from this binary.
                                 # If tracing a process that is running from
                                 # a dynamically-linked binary, this argument
                                 # is required and should be the path to the
                                 # pthread library.

    deadlock 181 --verbose
                                 # Analyze PID 181 and print statistics about
                                 # the mutex wait graph.

    deadlock 181 --lock-symbols my_mutex_lock1,my_mutex_lock2 \\
        --unlock-symbols my_mutex_unlock1,my_mutex_unlock2
                                 # Analyze PID 181 and trace custom mutex
                                 # symbols instead of pthread mutexes.

    deadlock 181 --dump-graph graph.json
                                 # Analyze PID 181 and dump the mutex wait
                                 # graph to graph.json.
    '''
    parser = argparse.ArgumentParser(
        description=(
            'Detect potential deadlocks (lock inversions) in a running binary.'
            '\nMust be run as root.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument('pid', type=int, help='Pid to trace')
    # Binaries with `:` in the path will fail to attach uprobes on kernels
    # running without this patch: https://lkml.org/lkml/2017/1/13/585.
    # Symlinks to the binary without `:` in the path can get around this issue.
    parser.add_argument(
        '--binary',
        type=str,
        default='',
        help='If set, trace the mutexes from the binary at this path. '
        'For statically-linked binaries, this argument is not required. '
        'For dynamically-linked binaries, this argument is required and '
        'should be the path of the pthread library the binary is using. '
        'Example: /lib/x86_64-linux-gnu/libpthread.so.0',
    )
    parser.add_argument(
        '--dump-graph',
        type=str,
        default='',
        help='If set, this will dump the mutex graph to the specified file.',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print statistics about the mutex wait graph.',
    )
    parser.add_argument(
        '--lock-symbols',
        type=strlist,
        default=['pthread_mutex_lock'],
        help='Comma-separated list of lock symbols to trace. Default is '
        'pthread_mutex_lock. These symbols cannot be inlined in the binary.',
    )
    parser.add_argument(
        '--unlock-symbols',
        type=strlist,
        default=['pthread_mutex_unlock'],
        help='Comma-separated list of unlock symbols to trace. Default is '
        'pthread_mutex_unlock. These symbols cannot be inlined in the binary.',
    )
    parser.add_argument(
        '-t', '--threads', type=int, default=65536,
        help='Specifies the maximum number of threads to trace. default 65536. '
             'Note. 40 bytes per thread.'
    )
    parser.add_argument(
        '-e', '--edges', type=int, default=65536,
        help='Specifies the maximum number of edge cases that can be recorded. '
             'default 65536. Note. 88 bytes per edge case.'
    )
    parser.add_argument(
        '-s', '--stacktraces', type=int, default=65536,
        help='Specifies the maximum number of stack traces that can be recorded. '
             'This number is rounded up to the next power of two.'
             'default 65536. Note. 1 kbytes vmalloced per stack trace.'
    )

    args = parser.parse_args()
    if not args.binary:
        try:
            args.binary = os.readlink('/proc/%d/exe' % args.pid)
        except OSError as e:
            print('%s. Is the process (pid=%d) running?' % (str(e), args.pid))
            sys.exit(1)

    with open(os.path.join(CWD, 'deadlock.c')) as f:
        text = f.read()
    text = text.replace('MAX_THREADS', str(args.threads));
    text = text.replace('MAX_EDGES', str(args.edges));
    text = text.replace('MAX_TRACES', str(args.stacktraces));
    bpf = BPF(text=text)

    # Trace where threads are created
    bpf.attach_kretprobe(event=bpf.get_syscall_fnname('clone'), fn_name='trace_clone')

    # We must trace unlock first, otherwise in the time we attached the probe
    # on lock() and have not yet attached the probe on unlock(), a thread can
    # acquire mutexes and release them, but the release events will not be
    # traced, resulting in noisy reports.
    for symbol in args.unlock_symbols:
        try:
            bpf.attach_uprobe(
                name=args.binary,
                sym=symbol,
                fn_name='trace_mutex_release',
                pid=args.pid,
            )
        except Exception as e:
            print('%s. Failed to attach to symbol: %s\nIs --binary argument missing?' % (str(e), symbol))
            sys.exit(1)
    for symbol in args.lock_symbols:
        try:
            bpf.attach_uprobe(
                name=args.binary,
                sym=symbol,
                fn_name='trace_mutex_acquire',
                pid=args.pid,
            )
        except Exception as e:
            print('%s. Failed to attach to symbol: %s' % (str(e), symbol))
            sys.exit(1)

    def print_stack_trace(stack_id):
        '''Closure that prints the symbolized stack trace.'''
        for addr in bpf.get_table('stack_traces').walk(stack_id):
            line = bpf.sym(addr, args.pid)
            # Try to symbolize with objdump if we cannot with bpf.
            if line == '[unknown]':
                symbol = symbolize_with_objdump(args.binary, addr)
                if symbol:
                    line = symbol
            print('@ %016x %s' % (addr, line))

    print('Tracing... Hit Ctrl-C to end.')
    while True:
        try:
            # Map of child thread pid -> parent info
            thread_info = {
                child.value: (parent.parent_pid, parent.stack_id, parent.comm)
                for child, parent in bpf.get_table('thread_to_parent').items()
            }

            # Mutex wait directed graph. Nodes are mutexes. Edge (A,B) exists
            # if there exists some thread T where lock(A) was called and
            # lock(B) was called before unlock(A) was called.
            graph = DiGraph()
            for key, leaf in bpf.get_table('edges').items():
                graph.add_edge(
                    key.mutex1,
                    key.mutex2,
                    thread_pid=leaf.thread_pid,
                    thread_comm=leaf.comm.decode('utf-8'),
                    first_mutex_stack_id=leaf.mutex1_stack_id,
                    second_mutex_stack_id=leaf.mutex2_stack_id,
                )
            if args.verbose:
                print(
                    'Mutexes: %d, Edges: %d' %
                    (len(graph.nodes()), len(graph.edges()))
                )
            if args.dump_graph:
                with open(args.dump_graph, 'w') as f:
                    data = graph.node_link_data()
                    f.write(json.dumps(data, indent=2))

            cycle = find_cycle(graph)
            if cycle:
                print_cycle(
                    args.binary, graph, cycle, thread_info, print_stack_trace
                )
                sys.exit(1)

            time.sleep(1)
        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
