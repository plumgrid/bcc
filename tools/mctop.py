#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mctop   Memcached key operation analysis tool
#         For Linux, uses BCC, eBPF.
#
# USAGE: mctop.py  -p PID
#
# This uses in-kernel eBPF maps to trace and analyze key access rates and
# objects. This can help to spot hot keys, and tune memcached usage for
# performance.
#
# Copyright 2019 Shopify, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Nov-2019   Dale Hamel   Created this.
# Inspired by the ruby tool of the same name by Marcus Barczak in 2012, see
# see also https://github.com/etsy/mctop
# see also https://github.com/tumblr/memkeys

from __future__ import print_function
from time import sleep, strftime, monotonic
from bcc import BPF, USDT, utils
from subprocess import call
from math import floor
from enum import Enum
import argparse
import sys
import select
import tty
import termios
import json

# FIXME refactor globals into class vars or explicit global singleton classes

class McCommand(Enum):
   START = 1
   END = 2
   GET = 3
   ADD = 4
   SET = 5
   REPLACE = 6
   PREPEND = 7
   APPEND = 8
   TOUCH = 9
   CAS = 10
   INRC = 11
   DECR = 12
   DELETE = 13

# FIXME better help
# arguments
examples = """examples:
    ./mctop -p PID          # memcached usage top, 1 second refresh
"""

supported_commands = [McCommand.GET, McCommand.ADD, McCommand.SET,
                      McCommand.REPLACE, McCommand.PREPEND,
                      McCommand.APPEND, McCommand.TOUCH, McCommand.CAS]
parser = argparse.ArgumentParser(
    description="Memcached top key analysis",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="process id to attach to")
parser.add_argument(
    "-o",
    "--output",
    action="store",
    help="save map data to /top/OUTPUT.json if 'D' is issued to dump the map")

parser.add_argument("-C", "--noclear", action="store_true", # Implies --no-footer?
                    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
                    help="maximum rows to print, default 20")
parser.add_argument('-c','--commands', action='append', default=[],
                    choices=[ cmd.name for cmd in supported_commands],
                    help="Command to trace, can specify many. Default is all." )
parser.add_argument("interval", nargs="?", default=1,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
parser.add_argument("--debug", action="store_true",
                    help="Enable printk debugging for eBPF probes")


# FIXME clean this up
args = parser.parse_args()
traced_commands = args.commands
if len(traced_commands) == 0:
    traced_commands=[cmd.name for cmd in supported_commands]

interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear) # FIXME ensure it still works with clear disabled
outfile = args.output
pid = args.pid

# Globals
exiting = 0
sort_mode = "C"  # FIXME allow specifying at runtime
selected_line = 0
selected_page = 0
selected_key  = ""
start_time    = 0
sort_ascending = True
view_mode = 1 # 1 - index, 2 - histogram
match_key = None
bpf = None
histogram_bpf = None
sorted_output = []

SELECTED_LINE_UP = 1
SELECTED_LINE_DOWN = -1
SELECTED_LINE_PAGE_UP = maxrows * -1
SELECTED_LINE_PAGE_DOWN = maxrows
SELECTED_LINE_START = "start"
SELECTED_LINE_END = "end"

sort_modes = {
    "C": "calls", # total calls to key
    "S": "size",  # latest size of key
    "R": "req/s", # requests per second to this key
    "B": "bw",    # total bytes accesses on this key
    "L": "lat"    # aggregate call latency for this key
}

commands = {
    "I": "insp", # inspect the latency of commands processing this key
    "T": "tgl",  # toggle sorting by ascending / descending order
    "W": "dmp",  # clear eBPF maps and dump to disk (if set)
    "Q": "quit"  # exit mctop
}
# FIXME have helper to generate per  type?
# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

#define READ_MASK 0xff // allow buffer reads up to 256 bytes
struct keyhit_t {
    char keystr[READ_MASK];
};

struct opcount_t {
    u64 get;
    u64 set;
};

struct value_t {
    u64 count;
    u64 bytecount;
    u64 totalbytes;
    u64 keysize;
    u64 timestamp;
    u64 latency;
    struct opcount_t opcount;
};

DEFINE_BPF_PRINTK_DEBUG
DEFINE_MC_COMMAND_ENUM

BPF_HASH(keyhits, struct keyhit_t, struct value_t);
BPF_HASH(comm_start, int32_t, u64);
BPF_HASH(lastkey, u64, struct keyhit_t);
BPF_HASH(calls_traced, u64, u64);
BPF_HASH(processed_commands, u64, u64);
BPF_HISTOGRAM(cmd_latency);

// FIXME this should use bitwise & over the 4 x 64 bit ints of the char buffer
// FIXME this is currently a prefix match
static inline bool match_key(const char * str) {
    DEFINE_KEY_MATCH

#ifdef KEY_MATCH
    char needle[] = "KEY_STRING";
    char haystack[sizeof(needle)];
    bpf_probe_read(&haystack, sizeof(haystack), (void *)str);
    for (int i = 0; i < sizeof(needle) - 1; ++i) {
            if (needle[i] != haystack[i]) {
                    return false;
            }
    }
    return true;

#else
    return false;
#endif // KEY_MATCH
}

int trace_command_start(struct pt_regs *ctx) {
    //u64 tid  = bpf_get_current_pid_tgid();
    int32_t conn_id = 0;
    bpf_usdt_readarg(1, ctx, &conn_id);
    u64 nsec = bpf_ktime_get_ns();
    comm_start.update(&conn_id, &nsec);
    return 0;
}

int trace_command_end(struct pt_regs *ctx) {
    struct keyhit_t *key;
    struct value_t *valp;
    int32_t conn_id = 0;
    u64 lastkey_id = 0;
    u64 nsec = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &conn_id);

    u64 *start = comm_start.lookup(&conn_id);

    processed_commands.increment(lastkey_id);

    if (start != NULL ) {
        u64 call_lat = nsec - *start;
        key = lastkey.lookup(&lastkey_id);

        if (key != NULL ) {
          valp = keyhits.lookup(key);
          if (valp) {
              valp->latency += call_lat;
          }
          DEFINE_KEY_MATCH
#ifdef KEY_MATCH
          if(match_key(key->keystr)) {

#ifdef BPF_PRINTK_DEBUG
              bpf_trace_printk("KEY HIT on %s LAT: %d\\n", key->keystr, call_lat);
#endif // BPF_PRINTK_DEBUG

              cmd_latency.increment(bpf_log2l(call_lat));
          }
#endif // KEY_MATCH
        }
    }
    return 0;
}

"""


# FIXME USDT args don't all use same types
trace_command_ebpf="""
int trace_command_COMMAND_NAME(struct pt_regs *ctx) {
    u64 keystr = 0;
    int32_t bytecount = 0; // type is -4@%eax in stap notes, which is int32

    uint8_t keysize = 0; // type is 1@%cl, which should be uint8
    struct keyhit_t keyhit = {0};
    struct value_t *valp, zero = {};
    char command_type_str[] = "COMMAND_NAME\\0";

    // GET and TOUCH selected because they sometimes use 64 bit int for keysize
    if ((COMMAND_ENUM_ID == MC_CMD_GET) ||
        (COMMAND_ENUM_ID == MC_CMD_TOUCH)) {
        bpf_usdt_readarg(3, ctx, &keysize);
        if (keysize == 0) {
            // GET command is annoying and has both int64 and int8 signatures
            u64 widekey = 0; // type on get command is 8@-32(%rbp), should be u64
            bpf_usdt_readarg(3, ctx, &widekey);
            keysize = widekey;
        }
    }
    else {
        bpf_usdt_readarg(3, ctx, &keysize);
    }

    bpf_usdt_readarg(2, ctx, &keystr);
    bpf_usdt_readarg(4, ctx, &bytecount);

    // see https://github.com/memcached/memcached/issues/576
    // as well as https://github.com/iovisor/bcc/issues/1260
    // we can convince the verifier the arbitrary read is safe using this
    // bitwise &, but only because our max buffer size happens to be 0xff,
    // which corresponds roughly to the the maximum key size of 250.
    // Since 256 bits is guaranteed to hold the key of 250, 0xff can be masked
    bpf_probe_read(&keyhit.keystr, keysize, (void *)keystr);

    u64 lastkey_id = 0;
    lastkey.update(&lastkey_id, &keyhit);

#ifdef BPF_PRINTK_DEBUG
    bpf_trace_printk("COMMAND: %s\\n", command_type_str);
    bpf_trace_printk("KEY: '%s' KEYSIZE: %d BYTES %d\\n", keyhit.keystr, keysize, bytecount);
#endif // BPF_PRINTK_DEBUG

    valp = keyhits.lookup_or_init(&keyhit, &zero);
    valp->count++;
    valp->keysize = keysize;
    valp->timestamp = bpf_ktime_get_ns();

    calls_traced.increment(lastkey_id);

    if (bytecount > 0) {
        valp->bytecount = bytecount;
        valp->totalbytes += bytecount;
    }

    // FIXME check all commands that should update bytecount
    if (COMMAND_ENUM_ID == MC_CMD_SET)
        valp->opcount.set++;
    else if (COMMAND_ENUM_ID == MC_CMD_GET)
        valp->opcount.get++;

#ifdef BPF_PRINTK_DEBUG
    bpf_trace_printk("KEY: '%s' GETS: %d SETS %d\\n", keyhit.keystr, valp->opcount.get, valp->opcount.set);
#endif // BPF_PRINTK_DEBUG
    return 0;
}
"""

def sort_output(unsorted_map):
    global sort_mode
    global sort_ascending

    output = unsorted_map
    if sort_mode == "C":
        output = sorted(output.items(), key=lambda x: x[1]['count'])
    elif sort_mode == "S":
        output = sorted(output.items(), key=lambda x: x[1]['bytecount'])
    elif sort_mode == "R":
        output = sorted(output.items(), key=lambda x: x[1]['cps'])
    elif sort_mode == "B":
        output = sorted(output.items(), key=lambda x: x[1]['bandwidth'])
    elif sort_mode == "L":
        output = sorted(output.items(), key=lambda x: x[1]['call_lat'])

    if sort_ascending:
        output = reversed(output)

    return list(output)

# Set stdin to non-blocking reads so we can poll for chars

def update_selected_key():
    global selected_key
    global selected_line

    if len(sorted_output) > 0 and len(sorted_output[selected_line]) > 0:
        selected_key = sorted_output[selected_line][0]

def change_selected_line(direction):
    global selected_line
    global selected_page
    global sorted_output
    global maxrows

    if direction == SELECTED_LINE_START:
        selected_line = 0
        selected_page = 0
        update_selected_key()
        return
    elif direction == SELECTED_LINE_END:
        selected_line = len(sorted_output) -1
        selected_page = floor(selected_line / maxrows)
        update_selected_key()
        return

    if direction > 0 and (selected_line + direction) >= len(sorted_output):
        if len(sorted_output) > 0:
            selected_line = len(sorted_output) - 1
        else:
            selected_line = 0
    elif direction < 0 and (selected_line + direction) <= 0:
        selected_line = 0
        selected_page = 0
    else:
        selected_line += direction
        selected_page = floor(selected_line / maxrows)

    update_selected_key()

def readKey(interval):
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(sys.stdin.fileno())
        new_settings = termios.tcgetattr(fd)
        new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)
        if select.select([sys.stdin], [], [], interval) == ([sys.stdin], [], []):
            key = sys.stdin.read(1)
            global sort_mode

            # TO DO - support "op types" here for histogram mode, lowercase
            #         will toggle to off, uppercase to on for collection
            #         eg, lowercase s in histogram mode to toggle the set
            #         command not to record histogram data, S to toggle it to
            #         on. Dump the histogram when these parameters are changed

            # FIXME allow for lower and uppercase to toggle into histogram mode
            # If no key is selected, latency should be recorded for all keys
            # FIXME implement Pause command
            if key.lower() == 't':
                global sort_ascending
                sort_ascending = not sort_ascending
            elif key == 'C':
                sort_mode = 'C'
            elif key == 'S':
                sort_mode = 'S' # FIXME make lowercase s 'select' to select key
            elif key == 'R':
                sort_mode = 'R'
            elif key == 'B':
                sort_mode = 'B'
            elif key == 'L':
                sort_mode = 'L'
            elif key == 'I':
                pass
                # TO DO - implement "inspect key', showing all data for the key
            elif key == 'H':
                global view_mode
                if view_mode == 2: # FIXME make this a named enum
                    view_mode = 1
                    bpf_init(False)
                else:
                    view_mode = 2
                    histogram_init(False)
            elif key.lower() == 'j':
                change_selected_line(SELECTED_LINE_UP)
            elif key.lower() == 'k':
                change_selected_line(SELECTED_LINE_DOWN)
            elif key.lower() == 'h': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_LEFT
            elif key.lower() == 'l': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_RIGHT
            elif key.lower() == 'u':
                change_selected_line(SELECTED_LINE_PAGE_UP)
            elif key.lower() == 'd':
                change_selected_line(SELECTED_LINE_PAGE_DOWN)
            elif key == 'g':
                change_selected_line(SELECTED_LINE_START)
            elif key == 'G':
                change_selected_line(SELECTED_LINE_END)
            elif key.lower() == 'w':
                 dump_map()
            elif key.lower() == 'q':
                print("QUITTING")
                global exiting
                exiting = 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# FIXME this should dump a full representation of the eBPF data in a reasonable
# schema
def dump_map():
    global outfile
    global bpf
    global sorted_output
    global selected_line
    global selected_page

    print("DUMPING DATA")
    if outfile is not None:
        out = open('/tmp/%s.json' % outfile, 'w')
        json_str = json.dumps(sorted_output)
        out.write(json_str)
        out.close

    # FIXME null check?
    bpf.get_table("keyhits").clear() # FIXME clear other maps
    sorted_output.clear()
    selected_line = 0
    selected_page = 0

# FIXME build from probe definition?
def build_probes(render_only):
    global pid
    global args
    global usdt
    global bpf_text
    global start_time
    global traced_commands
    global trace_command_ebpf
    rendered_text = bpf_text.replace("DEFINE_KEY_MATCH", "#define KEY_MATCH" if match_key != None else "") \
                            .replace("KEY_STRING", match_key if match_key != None else "")

    for _, val in enumerate(traced_commands):
        rendered_text += "\n" + trace_command_ebpf.replace('COMMAND_NAME',
                                                             val.lower())\
                                                  .replace('COMMAND_ENUM_ID',
                                                            "MC_CMD_%s"%(val))


    enum_text = "\n".join(["#define MC_CMD_%s %d" % (cmd.name, cmd.value) for cmd in McCommand])
    rendered_text = rendered_text.replace('DEFINE_MC_COMMAND_ENUM', enum_text)
    rendered_text = rendered_text.replace('DEFINE_BPF_PRINTK_DEBUG', '#define BPF_PRINTK_DEBUG 1' if args.debug else "")

    if render_only:
        print(rendered_text)
        exit()

    usdt = USDT(pid=pid)
    # FIXME use fully specified version, port this to python

    for _, val in enumerate(traced_commands):
        usdt.enable_probe(probe="command__%s" % (val.lower()),
                              fn_name="trace_command_%s" % (val.lower()))
    usdt.enable_probe(probe="process__command__start",
                                            fn_name="trace_command_start")
    usdt.enable_probe(probe="process__command__end",
                                            fn_name="trace_command_end")
    bpf = BPF(text=rendered_text, usdt_contexts=[usdt])
    start_time = bpf.monotonic_time()
    return bpf

def teardown_bpf():
    global bpf
    if bpf != None:
        dump_map()
        bpf.cleanup()
        del bpf

def histogram_init(dump_ebpf):
    global match_key
    global selected_key
    global bpf
    teardown_bpf()
    match_key = selected_key
    bpf = build_probes(dump_ebpf)

def bpf_init(dump_ebpf):
    global match_key
    global bpf
    teardown_bpf() # FIXME - avoid tearing down until a new match_key is selected?
    match_key = None
    bpf = build_probes(dump_ebpf)

def print_histogram():
    global bpf
    global match_key
    print("Latency histogram for key %s" % (match_key))
    bpf["cmd_latency"].print_log2_hist("nsec") # FIXME detect if this printed to buffer for footer?

    print("HISTOGRAM FOOTER")

def print_keylist():
    global bpf
    global maxrows
    global sorted_output
    global start_time
    global selected_key

    # FIXME better calculate the key width so that it can be shifted with h/l
    print("%-30s %8s %8s %8s %8s %8s" % ("MEMCACHED KEY", "CALLS",
                                         "OBJSIZE", "REQ/S",
                                         "BW(kbps)", "LAT(MS)"))
    keyhits = bpf.get_table("keyhits")
    interval = (bpf.monotonic_time() - start_time) / 1000000000

    data_map = {}
    for k, v in keyhits.items():
        shortkey = k.keystr[:v.keysize].decode('utf-8', 'replace')
        data_map[shortkey] = {
            "count": v.count,
            "bytecount": v.bytecount,
            "totalbytes": v.totalbytes,
            "timestamp": v.timestamp,
            "cps": v.count / interval,
            "bandwidth": (v.totalbytes / 1000) /interval if v.totalbytes > 0 else 0,
            "latency": v.latency,
            "call_lat": (v.latency / v.count) / 1000,
        }

    sorted_output = sort_output(data_map)

    max_pages = floor(len(sorted_output) / maxrows)

    printed_lines = 0
    for i, tup in enumerate(sorted_output):  # FIXME sort this
        global selected_line
        global selected_page

        k = tup[0]
        v = tup[1]
        fmt_start = ""
        fmt_end   = ""

        page = floor(int(i) / int(maxrows))

        if page != selected_page:
            continue

        if i == selected_line:
            fmt_start = "\033[1;30;47m" # White background, black text
            fmt_end   = "\033[1;0;0;0m"

        print("%s%-30s %8d %8d %8.2f %8.2f %8.2f%s" % (fmt_start, k, v['count'], v['bytecount'],
                                             v['cps'], v['bandwidth'],
                                             v['call_lat'], fmt_end) )
        printed_lines += 1

        if printed_lines >= maxrows:
            break

    print((maxrows - printed_lines) * "\r\n")
    calls_traced = bpf["calls_traced"].values()[0].value if len(bpf["calls_traced"].values()) > 0 else 0
    processed_commands= bpf["processed_commands"].values()[0].value if len(bpf["processed_commands"].values()) > 0 else 0
    print("[Selected key: %s | %d | %d]" % (selected_key, calls_traced, processed_commands) )
    sys.stdout.write("[Curr: %s/%s Opt: %s:%s|%s:%s|%s:%s|%s:%s|%s:%s]" %
                     (sort_mode,
                      "Asc" if sort_ascending else "Dsc",
                      'C', sort_modes['C'],
                      'S', sort_modes['S'],
                      'R', sort_modes['R'],
                      'B', sort_modes['B'],
                      'L', sort_modes['L']
                      ))

    sys.stdout.write("[%s:%s %s:%s %s:%s](%d/%d)" % (
        'T', commands['T'],
        'W', commands['W'],
        'Q', commands['Q'],
        selected_page + 1,
        max_pages + 1
    ))

def run():
    global args
    global exiting
    global bpf
    global start_time
    global view_mode
    global interval

    bpf_init(args.ebpf)
    first_loop = True

    start_time = bpf.monotonic_time()

    while True:
        try:
            if not first_loop:
                readKey(interval)
            else:
                first_loop = False
        except KeyboardInterrupt:
            exiting = 1

        # header
        if clear:
            print("\033c", end="")

        if view_mode == 1:
            print_keylist()
        elif view_mode == 2:
            print_histogram()
        print("\033[%d;%dH" % (0, 0))

        if exiting:
            print("\033c", end="")
            exit()
run()
