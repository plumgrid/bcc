# Copyright 2015 PLUMgrid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import atexit
import ctypes as ct
import fcntl
import json
import os
import re
import errno
import sys
import platform

from .libbcc import lib, bcc_symbol, bcc_symbol_option, bcc_stacktrace_build_id, _SYM_CB_TYPE
from .table import Table, PerfEventArray, RingBuf, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK
from .perf import Perf
from .utils import get_online_cpus, printb, _assert_is_bytes, ArgString, StrcmpRewrite
from .version import __version__
from .disassembler import disassemble_prog, decode_map
from .usdt import USDT, USDTException

try:
    basestring
except NameError:  # Python 3
    basestring = str

_default_probe_limit = 1000
_num_open_probes = 0

# for tests
def _get_num_open_probes():
    global _num_open_probes
    return _num_open_probes

DEBUGFS = "/sys/kernel/debug"
TRACEFS = os.path.join(DEBUGFS, "tracing")
if not os.path.exists(TRACEFS):
    TRACEFS = "/sys/kernel/tracing"

# Debug flags

# Debug output compiled LLVM IR.
DEBUG_LLVM_IR = 0x1
# Debug output loaded BPF bytecode and register state on branches.
DEBUG_BPF = 0x2
# Debug output pre-processor result.
DEBUG_PREPROCESSOR = 0x4
# Debug output ASM instructions embedded with source.
DEBUG_SOURCE = 0x8
# Debug output register state on all instructions in addition to DEBUG_BPF.
DEBUG_BPF_REGISTER_STATE = 0x10
# Debug BTF.
DEBUG_BTF = 0x20

class SymbolCache(object):
    def __init__(self, pid):
        self.cache = lib.bcc_symcache_new(
                pid, ct.cast(None, ct.POINTER(bcc_symbol_option)))

    def resolve(self, addr, demangle):
        """
        Return a tuple of the symbol (function), its offset from the beginning
        of the function, and the module in which it lies. For example:
            ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
        If the symbol cannot be found but we know which module it is in,
        return the module name and the offset from the beginning of the
        module. If we don't even know the module, return the absolute
        address as the offset.
        """

        sym = bcc_symbol()
        if demangle:
            res = lib.bcc_symcache_resolve(self.cache, addr, ct.byref(sym))
        else:
            res = lib.bcc_symcache_resolve_no_demangle(self.cache, addr,
                                                       ct.byref(sym))
        if res < 0:
            if sym.module and sym.offset:
                return (None, sym.offset,
                        ct.cast(sym.module, ct.c_char_p).value)
            return (None, addr, None)
        if demangle:
            name_res = sym.demangle_name
            lib.bcc_symbol_free_demangle_name(ct.byref(sym))
        else:
            name_res = sym.name
        return (name_res, sym.offset, ct.cast(sym.module, ct.c_char_p).value)

    def resolve_name(self, module, name):
        module = _assert_is_bytes(module)
        name = _assert_is_bytes(name)
        addr = ct.c_ulonglong()
        if lib.bcc_symcache_resolve_name(self.cache, module, name,
                ct.byref(addr)) < 0:
            return -1
        return addr.value

class PerfType:
    # From perf_type_id in uapi/linux/perf_event.h
    HARDWARE = 0
    SOFTWARE = 1
    TRACEPOINT = 2
    HW_CACHE = 3
    RAW = 4
    BREAKPOINT = 5

class PerfHWConfig:
    # From perf_hw_id in uapi/linux/perf_event.h
    CPU_CYCLES = 0
    INSTRUCTIONS = 1
    CACHE_REFERENCES = 2
    CACHE_MISSES = 3
    BRANCH_INSTRUCTIONS = 4
    BRANCH_MISSES = 5
    BUS_CYCLES = 6
    STALLED_CYCLES_FRONTEND = 7
    STALLED_CYCLES_BACKEND = 8
    REF_CPU_CYCLES = 9

class PerfSWConfig:
    # From perf_sw_id in uapi/linux/perf_event.h
    CPU_CLOCK = 0
    TASK_CLOCK = 1
    PAGE_FAULTS = 2
    CONTEXT_SWITCHES = 3
    CPU_MIGRATIONS = 4
    PAGE_FAULTS_MIN = 5
    PAGE_FAULTS_MAJ = 6
    ALIGNMENT_FAULTS = 7
    EMULATION_FAULTS = 8
    DUMMY = 9
    BPF_OUTPUT = 10

class PerfEventSampleFormat:
    # from perf_event_sample_format in uapi/linux/bpf.h
    IP = (1 << 0)
    TID = (1 << 1)
    TIME = (1 << 2)
    ADDR = (1 << 3)
    READ = (1 << 4)
    CALLCHAIN = (1 << 5)
    ID = (1 << 6)
    CPU = (1 << 7)
    PERIOD = (1 << 8)
    STREAM_ID = (1 << 9)
    RAW = (1 << 10)
    BRANCH_STACK = (1 << 11)
    REGS_USER = (1 << 12)
    STACK_USER = (1 << 13)
    WEIGHT = (1 << 14)
    DATA_SRC = (1 << 15)
    IDENTIFIER = (1 << 16)
    TRANSACTION = (1 << 17)
    REGS_INTR = (1 << 18)
    PHYS_ADDR = (1 << 19)
    AUX = (1 << 20)
    CGROUP = (1 << 21)
    DATA_PAGE_SIZE = (1 << 22)
    CODE_PAGE_SIZE = (1 << 23)
    WEIGHT_STRUCT = (1 << 24)

class BPFProgType:
    # From bpf_prog_type in uapi/linux/bpf.h
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5
    XDP = 6
    PERF_EVENT = 7
    CGROUP_SKB = 8
    CGROUP_SOCK = 9
    LWT_IN = 10
    LWT_OUT = 11
    LWT_XMIT = 12
    SOCK_OPS = 13
    SK_SKB = 14
    CGROUP_DEVICE = 15
    SK_MSG = 16
    RAW_TRACEPOINT = 17
    CGROUP_SOCK_ADDR = 18
    CGROUP_SOCKOPT = 25
    TRACING = 26
    LSM = 29

class BPFAttachType:
    # from bpf_attach_type uapi/linux/bpf.h
    CGROUP_INET_INGRESS = 0
    CGROUP_INET_EGRESS = 1
    CGROUP_INET_SOCK_CREATE = 2
    CGROUP_SOCK_OPS = 3
    SK_SKB_STREAM_PARSER = 4
    SK_SKB_STREAM_VERDICT = 5
    CGROUP_DEVICE = 6
    SK_MSG_VERDICT = 7
    CGROUP_INET4_BIND = 8
    CGROUP_INET6_BIND = 9
    CGROUP_INET4_CONNECT = 10
    CGROUP_INET6_CONNECT = 11
    CGROUP_INET4_POST_BIND = 12
    CGROUP_INET6_POST_BIND = 13
    CGROUP_UDP4_SENDMSG = 14
    CGROUP_UDP6_SENDMSG = 15
    LIRC_MODE2 = 16
    FLOW_DISSECTOR = 17
    CGROUP_SYSCTL = 18
    CGROUP_UDP4_RECVMSG = 19
    CGROUP_UDP6_RECVMSG = 20
    CGROUP_GETSOCKOPT = 21
    CGROUP_SETSOCKOPT = 22
    TRACE_RAW_TP = 23
    TRACE_FENTRY = 24
    TRACE_FEXIT  = 25
    MODIFY_RETURN = 26
    LSM_MAC = 27
    TRACE_ITER = 28
    CGROUP_INET4_GETPEERNAME = 29
    CGROUP_INET6_GETPEERNAME = 30
    CGROUP_INET4_GETSOCKNAME = 31
    CGROUP_INET6_GETSOCKNAME = 32
    XDP_DEVMAP = 33
    CGROUP_INET_SOCK_RELEASE = 34
    XDP_CPUMAP = 35
    SK_LOOKUP = 36
    XDP = 37
    SK_SKB_VERDICT = 38

class XDPAction:
    # from xdp_action uapi/linux/bpf.h
    XDP_ABORTED = 0
    XDP_DROP = 1
    XDP_PASS = 2
    XDP_TX = 3
    XDP_REDIRECT = 4

class XDPFlags:
    # from xdp_flags uapi/linux/if_link.h
    # unlike similar enum-type holder classes in this file, source for these
    # is #define XDP_FLAGS_UPDATE_IF_NOEXIST, #define XDP_FLAGS_SKB_MODE, ...
    UPDATE_IF_NOEXIST = (1 << 0)
    SKB_MODE = (1 << 1)
    DRV_MODE = (1 << 2)
    HW_MODE = (1 << 3)
    REPLACE = (1 << 4)

class BPF(object):
    # Here for backwards compatibility only, add new enum members and types
    # the appropriate wrapper class elsewhere in this file to avoid namespace
    # collision issues
    SOCKET_FILTER = BPFProgType.SOCKET_FILTER
    KPROBE = BPFProgType.KPROBE
    SCHED_CLS = BPFProgType.SCHED_CLS
    SCHED_ACT = BPFProgType.SCHED_ACT
    TRACEPOINT = BPFProgType.TRACEPOINT
    XDP = BPFProgType.XDP
    PERF_EVENT = BPFProgType.PERF_EVENT
    CGROUP_SKB = BPFProgType.CGROUP_SKB
    CGROUP_SOCK = BPFProgType.CGROUP_SOCK
    LWT_IN = BPFProgType.LWT_IN
    LWT_OUT = BPFProgType.LWT_OUT
    LWT_XMIT = BPFProgType.LWT_XMIT
    SOCK_OPS = BPFProgType.SOCK_OPS
    SK_SKB = BPFProgType.SK_SKB
    CGROUP_DEVICE = BPFProgType.CGROUP_DEVICE
    SK_MSG = BPFProgType.SK_MSG
    RAW_TRACEPOINT = BPFProgType.RAW_TRACEPOINT
    CGROUP_SOCK_ADDR = BPFProgType.CGROUP_SOCK_ADDR
    TRACING = BPFProgType.TRACING
    LSM = BPFProgType.LSM

    XDP_ABORTED = XDPAction.XDP_ABORTED
    XDP_DROP = XDPAction.XDP_DROP
    XDP_PASS = XDPAction.XDP_PASS
    XDP_TX = XDPAction.XDP_TX
    XDP_REDIRECT = XDPAction.XDP_REDIRECT

    XDP_FLAGS_UPDATE_IF_NOEXIST = XDPFlags.UPDATE_IF_NOEXIST
    XDP_FLAGS_SKB_MODE = XDPFlags.SKB_MODE
    XDP_FLAGS_DRV_MODE = XDPFlags.DRV_MODE
    XDP_FLAGS_HW_MODE = XDPFlags.HW_MODE
    XDP_FLAGS_REPLACE = XDPFlags.REPLACE
    # END enum backwards compat

    _probe_repl = re.compile(b"[^a-zA-Z0-9_]")
    _sym_caches = {}
    _bsymcache = lib.bcc_buildsymcache_new()

    _auto_includes = {
        "linux/time.h": ["time"],
        "linux/fs.h": ["fs", "file"],
        "linux/blkdev.h": ["bio", "request"],
        "linux/slab.h": ["alloc"],
        "linux/netdevice.h": ["sk_buff", "net_device"]
    }

    _syscall_prefixes = [
        b"sys_",
        b"__x64_sys_",
        b"__x32_compat_sys_",
        b"__ia32_compat_sys_",
        b"__arm64_sys_",
        b"__s390x_sys_",
        b"__s390_sys_",
        b"__riscv_sys_",
    ]

    # BPF timestamps come from the monotonic clock. To be able to filter
    # and compare them from Python, we need to invoke clock_gettime.
    # Adapted from http://stackoverflow.com/a/1205762
    CLOCK_MONOTONIC = 1         # see <linux/time.h>

    class timespec(ct.Structure):
        _fields_ = [('tv_sec', ct.c_long), ('tv_nsec', ct.c_long)]

    _librt = ct.CDLL('librt.so.1', use_errno=True)
    _clock_gettime = _librt.clock_gettime
    _clock_gettime.argtypes = [ct.c_int, ct.POINTER(timespec)]

    @classmethod
    def monotonic_time(cls):
        """monotonic_time()
        Returns the system monotonic time from clock_gettime, using the
        CLOCK_MONOTONIC constant. The time returned is in nanoseconds.
        """
        t = cls.timespec()
        if cls._clock_gettime(cls.CLOCK_MONOTONIC, ct.byref(t)) != 0:
            errno = ct.get_errno()
            raise OSError(errno, os.strerror(errno))
        return t.tv_sec * 1e9 + t.tv_nsec

    @classmethod
    def generate_auto_includes(cls, program_words):
        """
        Generates #include statements automatically based on a set of
        recognized types such as sk_buff and bio. The input is all the words
        that appear in the BPF program, and the output is a (possibly empty)
        string of #include statements, such as "#include <linux/fs.h>".
        """
        headers = ""
        for header, keywords in cls._auto_includes.items():
            for keyword in keywords:
                for word in program_words:
                    if keyword in word and header not in headers:
                        headers += "#include <%s>\n" % header
        return headers

    # defined for compatibility reasons, to be removed
    Table = Table

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    @staticmethod
    def _find_file(filename):
        """ If filename is invalid, search in ./ of argv[0] """
        if filename:
            if not os.path.isfile(filename):
                argv0 = ArgString(sys.argv[0])
                t = b"/".join([os.path.abspath(os.path.dirname(argv0.__bytes__())), filename])
                if os.path.isfile(t):
                    filename = t
                else:
                    raise Exception("Could not find file %s" % filename)
        return filename

    @staticmethod
    def find_exe(bin_path):
        """
        find_exe(bin_path)

        Traverses the PATH environment variable, looking for the first
        directory that contains an executable file named bin_path, and
        returns the full path to that file, or None if no such file
        can be found. This is meant to replace invocations of the
        "which" shell utility, which doesn't have portable semantics
        for skipping aliases.
        """
        # Source: http://stackoverflow.com/a/377028
        def is_exe(fpath):
            return os.path.isfile(fpath) and \
                os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(bin_path)
        if fpath:
            if is_exe(bin_path):
                return bin_path
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path.encode(), bin_path)
                if is_exe(exe_file):
                    return exe_file
        return None

    def __init__(self, src_file=b"", hdr_file=b"", text=None, debug=0,
            cflags=[], usdt_contexts=[], allow_rlimit=True, device=None,
            attach_usdt_ignore_pid=False):
        """Create a new BPF module with the given source code.

        Note:
            All fields are marked as optional, but either `src_file` or `text`
            must be supplied, and not both.

        Args:
            src_file (Optional[str]): Path to a source file for the module
            hdr_file (Optional[str]): Path to a helper header file for the `src_file`
            text (Optional[str]): Contents of a source file for the module
            debug (Optional[int]): Flags used for debug prints, can be |'d together
                                   See "Debug flags" for explanation
        """

        src_file = _assert_is_bytes(src_file)
        hdr_file = _assert_is_bytes(hdr_file)
        text = _assert_is_bytes(text)

        assert not (text and src_file)

        # Fix 'larchintrin.h' file not found error for loongarch64
        architecture = platform.machine()
        if architecture == 'loongarch64':
            # get clang include path
            try:
                clang_include_path_output = subprocess.check_output(['clang', '-print-file-name=include'], stderr=subprocess.STDOUT)
                clang_include_path_str = clang_include_path_output.decode('utf-8').strip('\n')
                if not os.path.exists(clang_include_path_str):
                    clang_include_path_str = False
            except Exception as e:
                clang_include_path_str = False
            # get gcc include path
            try:
                gcc_include_path_output = subprocess.check_output(['gcc', '-print-file-name=include'], stderr=subprocess.STDOUT)
                gcc_include_path_str = gcc_include_path_output.decode('utf-8').strip('\n')
                if not os.path.exists(gcc_include_path_str):
                    gcc_include_path_str = False
            except Exception as e:
                gcc_include_path_str = False
            # add clang and gcc include path for cflags
            if clang_include_path_str:
                cflags.append("-I" + clang_include_path_str)
            if gcc_include_path_str:
                cflags.append("-I" + gcc_include_path_str)

        self.kprobe_fds = {}
        self.uprobe_fds = {}
        self.tracepoint_fds = {}
        self.raw_tracepoint_fds = {}
        self.kfunc_entry_fds = {}
        self.kfunc_exit_fds = {}
        self.lsm_fds = {}
        self.perf_buffers = {}
        self.open_perf_events = {}
        self._ringbuf_manager = None
        self.tracefile = None
        atexit.register(self.cleanup)

        self.debug = debug
        self.funcs = {}
        self.tables = {}
        self.module = None
        cflags_array = (ct.c_char_p * len(cflags))()
        for i, s in enumerate(cflags): cflags_array[i] = bytes(ArgString(s))

        if src_file:
            src_file = BPF._find_file(src_file)
            hdr_file = BPF._find_file(hdr_file)

        if src_file:
            # Read the BPF C source file into the text variable. This ensures,
            # that files and inline text are treated equally.
            with open(src_file, mode="rb") as file:
                text = file.read()

        ctx_array = (ct.c_void_p * len(usdt_contexts))()
        for i, usdt in enumerate(usdt_contexts):
            ctx_array[i] = ct.c_void_p(usdt.get_context())
        usdt_text = lib.bcc_usdt_genargs(ctx_array, len(usdt_contexts))
        if usdt_text is None:
            raise Exception("can't generate USDT probe arguments; " +
                            "possible cause is missing pid when a " +
                            "probe in a shared object has multiple " +
                            "locations")
        text = usdt_text + text


        self.module = lib.bpf_module_create_c_from_string(text,
                                                          self.debug,
                                                          cflags_array, len(cflags_array),
                                                          allow_rlimit, device)
        if not self.module:
            raise Exception("Failed to compile BPF module %s" % (src_file or "<text>"))

        for usdt_context in usdt_contexts:
            usdt_context.attach_uprobes(self, attach_usdt_ignore_pid)

        # If any "kprobe__" or "tracepoint__" or "raw_tracepoint__"
        # prefixed functions were defined,
        # they will be loaded and attached here.
        self._trace_autoload()

    def load_funcs(self, prog_type=KPROBE):
        """load_funcs(prog_type=KPROBE)

        Load all functions in this BPF module with the given type.
        Returns a list of the function handles."""

        fns = []
        for i in range(0, lib.bpf_num_functions(self.module)):
            func_name = lib.bpf_function_name(self.module, i)
            fns.append(self.load_func(func_name, prog_type))

        return fns

    def load_func(self, func_name, prog_type, device = None, attach_type = -1):
        func_name = _assert_is_bytes(func_name)
        if func_name in self.funcs:
            return self.funcs[func_name]
        if not lib.bpf_function_start(self.module, func_name):
            raise Exception("Unknown program %s" % func_name)
        log_level = 0
        if (self.debug & DEBUG_BPF_REGISTER_STATE):
            log_level = 2
        elif (self.debug & DEBUG_BPF):
            log_level = 1
        fd = lib.bcc_func_load(self.module, prog_type, func_name,
                lib.bpf_function_start(self.module, func_name),
                lib.bpf_function_size(self.module, func_name),
                lib.bpf_module_license(self.module),
                lib.bpf_module_kern_version(self.module),
                log_level, None, 0, device, attach_type)

        if fd < 0:
            atexit.register(self.donothing)
            if ct.get_errno() == errno.EPERM:
                raise Exception("Need super-user privileges to run")

            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to load BPF program %s: %s" %
                            (func_name, errstr))

        fn = BPF.Function(self, func_name, fd)
        self.funcs[func_name] = fn

        return fn

    def dump_func(self, func_name):
        """
        Return the eBPF bytecodes for the specified function as a string
        """
        func_name = _assert_is_bytes(func_name)
        if not lib.bpf_function_start(self.module, func_name):
            raise Exception("Unknown program %s" % func_name)

        start, = lib.bpf_function_start(self.module, func_name),
        size, = lib.bpf_function_size(self.module, func_name),
        return ct.string_at(start, size)

    def disassemble_func(self, func_name):
        bpfstr = self.dump_func(func_name)
        return disassemble_prog(func_name, bpfstr)

    def decode_table(self, table_name, sizeinfo=False):
        table_obj = self[table_name]
        table_type = lib.bpf_table_type_id(self.module, table_obj.map_id)
        return decode_map(table_name, table_obj, table_type, sizeinfo=sizeinfo)

    str2ctype = {
        u"_Bool": ct.c_bool,
        u"char": ct.c_char,
        u"wchar_t": ct.c_wchar,
        u"unsigned char": ct.c_ubyte,
        u"short": ct.c_short,
        u"unsigned short": ct.c_ushort,
        u"int": ct.c_int,
        u"unsigned int": ct.c_uint,
        u"long": ct.c_long,
        u"unsigned long": ct.c_ulong,
        u"long long": ct.c_longlong,
        u"unsigned long long": ct.c_ulonglong,
        u"float": ct.c_float,
        u"double": ct.c_double,
        u"long double": ct.c_longdouble,
        u"__int128": ct.c_int64 * 2,
        u"unsigned __int128": ct.c_uint64 * 2,
    }
    @staticmethod
    def _decode_table_type(desc):
        if isinstance(desc, basestring):
            return BPF.str2ctype[desc]
        anon = []
        fields = []
        for t in desc[1]:
            if len(t) == 2:
                fields.append((t[0], BPF._decode_table_type(t[1])))
            elif len(t) == 3:
                if isinstance(t[2], list):
                    fields.append((t[0], BPF._decode_table_type(t[1]) * t[2][0]))
                elif isinstance(t[2], int):
                    fields.append((t[0], BPF._decode_table_type(t[1]), t[2]))
                elif isinstance(t[2], basestring) and (
                        t[2] == u"union" or t[2] == u"struct" or
                        t[2] == u"struct_packed"):
                    name = t[0]
                    if name == "":
                        name = "__anon%d" % len(anon)
                        anon.append(name)
                    fields.append((name, BPF._decode_table_type(t)))
                else:
                    raise Exception("Failed to decode type %s" % str(t))
            else:
                raise Exception("Failed to decode type %s" % str(t))
        base = ct.Structure
        is_packed = False
        if len(desc) > 2:
            if desc[2] == u"union":
                base = ct.Union
            elif desc[2] == u"struct":
                base = ct.Structure
            elif desc[2] == u"struct_packed":
                base = ct.Structure
                is_packed = True
        if is_packed:
            cls = type(str(desc[0]), (base,), dict(_anonymous_=anon, _pack_=1,
                _fields_=fields))
        else:
            cls = type(str(desc[0]), (base,), dict(_anonymous_=anon,
                _fields_=fields))
        return cls

    def get_table(self, name, keytype=None, leaftype=None, reducer=None):
        name = _assert_is_bytes(name)
        map_id = lib.bpf_table_id(self.module, name)
        map_fd = lib.bpf_table_fd(self.module, name)
        is_queuestack = lib.bpf_table_type_id(self.module, map_id) in [BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK]
        if map_fd < 0:
            raise KeyError
        if not keytype and not is_queuestack:
            key_desc = lib.bpf_table_key_desc(self.module, name).decode("utf-8")
            if not key_desc:
                raise Exception("Failed to load BPF Table %s key desc" % name)
            keytype = BPF._decode_table_type(json.loads(key_desc))
        if not leaftype:
            leaf_desc = lib.bpf_table_leaf_desc(self.module, name).decode("utf-8")
            if not leaf_desc:
                raise Exception("Failed to load BPF Table %s leaf desc" % name)
            leaftype = BPF._decode_table_type(json.loads(leaf_desc))
        return Table(self, map_id, map_fd, keytype, leaftype, name, reducer=reducer)

    def __getitem__(self, key):
        if key not in self.tables:
            self.tables[key] = self.get_table(key)
        return self.tables[key]

    def __setitem__(self, key, leaf):
        self.tables[key] = leaf

    def __len__(self):
        return len(self.tables)

    def __delitem__(self, key):
        del self.tables[key]

    def __iter__(self):
        return self.tables.__iter__()

    @staticmethod
    def attach_func(fn, attachable_fd, attach_type, flags=0):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")

        res = lib.bpf_prog_attach(fn.fd, attachable_fd, attach_type, flags)
        if res < 0:
            raise Exception("Failed to attach BPF function with attach_type "\
                            "{0}: {1}".format(attach_type, os.strerror(-res)))

    @staticmethod
    def detach_func(fn, attachable_fd, attach_type):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")

        res = lib.bpf_prog_detach2(fn.fd, attachable_fd, attach_type)
        if res < 0:
            raise Exception("Failed to detach BPF function with attach_type "\
                            "{0}: {1}".format(attach_type, os.strerror(-res)))

    @staticmethod
    def attach_raw_socket(fn, dev):
        dev = _assert_is_bytes(dev)
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        sock = lib.bpf_open_raw_sock(dev)
        if sock < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to open raw device %s: %s" % (dev, errstr))
        res = lib.bpf_attach_socket(sock, fn.fd)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to attach BPF to device %s: %s"
                    % (dev, errstr))
        fn.sock = sock

    @staticmethod
    def get_kprobe_functions(event_re):
        blacklist_file = "%s/kprobes/blacklist" % DEBUGFS
        try:
            with open(blacklist_file, "rb") as blacklist_f:
                blacklist = set([line.rstrip().split()[1] for line in blacklist_f])
        except IOError as e:
            if e.errno != errno.EPERM:
                raise e
            blacklist = set([])

        avail_filter_file = "%s/tracing/available_filter_functions" % DEBUGFS
        try:
            with open(avail_filter_file, "rb") as avail_filter_f:
                avail_filter = set([line.rstrip().split()[0] for line in avail_filter_f])
        except IOError as e:
            if e.errno != errno.EPERM:
                raise e
            avail_filter = set([])

        fns = []

        in_init_section = 0
        in_irq_section = 0
        with open("/proc/kallsyms", "rb") as avail_file:
            for line in avail_file:
                (t, fn) = line.rstrip().split()[1:3]
                # Skip all functions defined between __init_begin and
                # __init_end
                if in_init_section == 0:
                    if fn == b'__init_begin':
                        in_init_section = 1
                        continue
                elif in_init_section == 1:
                    if fn == b'__init_end':
                        in_init_section = 2
                        continue
                # Skip all functions defined between __irqentry_text_start and
                # __irqentry_text_end
                if in_irq_section == 0:
                    if fn == b'__irqentry_text_start':
                        in_irq_section = 1
                        continue
                    # __irqentry_text_end is not always after
                    # __irqentry_text_start. But only happens when
                    # no functions between two irqentry_text
                    elif fn == b'__irqentry_text_end':
                        in_irq_section = 2
                        continue
                elif in_irq_section == 1:
                    if fn == b'__irqentry_text_end':
                        in_irq_section = 2
                        continue
                # All functions defined as NOKPROBE_SYMBOL() start with the
                # prefix _kbl_addr_*, blacklisting them by looking at the name
                # allows to catch also those symbols that are defined in kernel
                # modules.
                if fn.startswith(b'_kbl_addr_'):
                    continue
                # Explicitly blacklist perf-related functions, they are all
                # non-attachable.
                elif fn.startswith(b'__perf') or fn.startswith(b'perf_'):
                    continue
                # Exclude all static functions with prefix __SCT__, they are
                # all non-attachable
                elif fn.startswith(b'__SCT__'):
                    continue
                # Exclude all gcc 8's extra .cold functions
                elif re.match(br'^.*\.cold(\.\d+)?$', fn):
                    continue
                if (t.lower() in [b't', b'w']) and re.fullmatch(event_re, fn) \
                    and fn not in blacklist \
                    and fn in avail_filter:
                    fns.append(fn)
        return set(fns)     # Some functions may appear more than once

    def _check_probe_quota(self, num_new_probes):
        global _num_open_probes
        if _num_open_probes + num_new_probes > BPF.get_probe_limit():
            raise Exception("Number of open probes would exceed global quota")

    @staticmethod
    def get_probe_limit():
        env_probe_limit = os.environ.get('BCC_PROBE_LIMIT')
        if env_probe_limit and env_probe_limit.isdigit():
            return int(env_probe_limit)
        else:
            return _default_probe_limit

    def _add_kprobe_fd(self, ev_name, fn_name, fd):
        global _num_open_probes
        if ev_name not in self.kprobe_fds:
            self.kprobe_fds[ev_name] = {}
        self.kprobe_fds[ev_name][fn_name] = fd
        _num_open_probes += 1

    def _del_kprobe_fd(self, ev_name, fn_name):
        global _num_open_probes
        del self.kprobe_fds[ev_name][fn_name]
        _num_open_probes -= 1

    def _add_uprobe_fd(self, name, fd):
        global _num_open_probes
        self.uprobe_fds[name] = fd
        _num_open_probes += 1

    def _del_uprobe_fd(self, name):
        global _num_open_probes
        del self.uprobe_fds[name]
        _num_open_probes -= 1

    # Find current system's syscall prefix by testing on the BPF syscall.
    # If no valid value found, will return the first possible value which
    # would probably lead to error in later API calls.
    def get_syscall_prefix(self):
        for prefix in self._syscall_prefixes:
            if self.ksymname(b"%sbpf" % prefix) != -1:
                return prefix
        return self._syscall_prefixes[0]

    # Given a syscall's name, return the full Kernel function name with current
    # system's syscall prefix. For example, given "clone" the helper would
    # return "sys_clone" or "__x64_sys_clone".
    def get_syscall_fnname(self, name):
        name = _assert_is_bytes(name)
        return self.get_syscall_prefix() + name

    # Given a Kernel function name that represents a syscall but already has a
    # prefix included, transform it to current system's prefix. For example,
    # if "sys_clone" provided, the helper may translate it to "__x64_sys_clone".
    def fix_syscall_fnname(self, name):
        name = _assert_is_bytes(name)
        for prefix in self._syscall_prefixes:
            if name.startswith(prefix):
                return self.get_syscall_fnname(name[len(prefix):])
        return name

    def attach_kprobe(self, event=b"", event_off=0, fn_name=b"", event_re=b""):
        event = _assert_is_bytes(event)
        fn_name = _assert_is_bytes(fn_name)
        event_re = _assert_is_bytes(event_re)

        # allow the caller to glob multiple functions together
        if event_re:
            matches = BPF.get_kprobe_functions(event_re)
            self._check_probe_quota(len(matches))
            failed = 0
            probes = []
            for line in matches:
                try:
                    self.attach_kprobe(event=line, fn_name=fn_name)
                except:
                    failed += 1
                    probes.append(line)
            if failed == len(matches):
                raise Exception("Failed to attach BPF program %s to kprobe %s"
                                ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                                (fn_name, '/'.join(probes)))
            return

        self._check_probe_quota(1)
        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = b"p_" + event.replace(b"+", b"_").replace(b".", b"_")
        fd = lib.bpf_attach_kprobe(fn.fd, 0, ev_name, event, event_off, 0)
        if fd < 0:
            raise Exception("Failed to attach BPF program %s to kprobe %s"
                            ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                            (fn_name, event))
        self._add_kprobe_fd(ev_name, fn_name, fd)
        return self

    def attach_kretprobe(self, event=b"", fn_name=b"", event_re=b"", maxactive=0):
        event = _assert_is_bytes(event)
        fn_name = _assert_is_bytes(fn_name)
        event_re = _assert_is_bytes(event_re)

        # allow the caller to glob multiple functions together
        if event_re:
            matches = BPF.get_kprobe_functions(event_re)
            failed = 0
            probes = []
            for line in matches:
                try:
                    self.attach_kretprobe(event=line, fn_name=fn_name,
                                          maxactive=maxactive)
                except:
                    failed += 1
                    probes.append(line)
            if failed == len(matches):
                raise Exception("Failed to attach BPF program %s to kretprobe %s"
                                ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                                (fn_name, '/'.join(probes)))
            return

        self._check_probe_quota(1)
        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = b"r_" + event.replace(b"+", b"_").replace(b".", b"_")
        fd = lib.bpf_attach_kprobe(fn.fd, 1, ev_name, event, 0, maxactive)
        if fd < 0:
            raise Exception("Failed to attach BPF program %s to kretprobe %s"
                            ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                            (fn_name, event))
        self._add_kprobe_fd(ev_name, fn_name, fd)
        return self

    def detach_kprobe_event(self, ev_name):
        ev_name = _assert_is_bytes(ev_name)
        fn_names = list(self.kprobe_fds[ev_name].keys())
        for fn_name in fn_names:
            self.detach_kprobe_event_by_fn(ev_name, fn_name)

    def detach_kprobe_event_by_fn(self, ev_name, fn_name):
        ev_name = _assert_is_bytes(ev_name)
        fn_name = _assert_is_bytes(fn_name)
        if ev_name not in self.kprobe_fds:
            raise Exception("Kprobe %s is not attached" % ev_name)
        res = lib.bpf_close_perf_event_fd(self.kprobe_fds[ev_name][fn_name])
        if res < 0:
            raise Exception("Failed to close kprobe FD")
        self._del_kprobe_fd(ev_name, fn_name)
        if len(self.kprobe_fds[ev_name]) == 0:
            res = lib.bpf_detach_kprobe(ev_name)
            if res < 0:
                raise Exception("Failed to detach BPF from kprobe")

    def detach_kprobe(self, event, fn_name=None):
        event = _assert_is_bytes(event)
        ev_name = b"p_" + event.replace(b"+", b"_").replace(b".", b"_")
        if fn_name:
            fn_name = _assert_is_bytes(fn_name)
            self.detach_kprobe_event_by_fn(ev_name, fn_name)
        else:
            self.detach_kprobe_event(ev_name)

    def detach_kretprobe(self, event, fn_name=None):
        event = _assert_is_bytes(event)
        ev_name = b"r_" + event.replace(b"+", b"_").replace(b".", b"_")
        if fn_name:
            fn_name = _assert_is_bytes(fn_name)
            self.detach_kprobe_event_by_fn(ev_name, fn_name)
        else:
            self.detach_kprobe_event(ev_name)

    @staticmethod
    def attach_xdp(dev, fn, flags=0):
        '''
            This function attaches a BPF function to a device on the device
            driver level (XDP)
        '''
        dev = _assert_is_bytes(dev)
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        res = lib.bpf_attach_xdp(dev, fn.fd, flags)
        if res < 0:
            err_no = ct.get_errno()
            if err_no == errno.EBADMSG:
                raise Exception("Internal error while attaching BPF to device,"+
                    " try increasing the debug level!")
            else:
                errstr = os.strerror(err_no)
                raise Exception("Failed to attach BPF to device %s: %s"
                            % (dev, errstr))

    @staticmethod
    def remove_xdp(dev, flags=0):
        '''
            This function removes any BPF function from a device on the
            device driver level (XDP)
        '''
        dev = _assert_is_bytes(dev)
        res = lib.bpf_attach_xdp(dev, -1, flags)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to detach BPF from device %s: %s"
                            % (dev, errstr))

    @classmethod
    def _check_path_symbol(cls, module, symname, addr, pid, sym_off=0):
        module = _assert_is_bytes(module)
        symname = _assert_is_bytes(symname)
        sym = bcc_symbol()
        c_pid = 0 if pid == -1 else pid
        if lib.bcc_resolve_symname(
            module, symname,
            addr or 0x0, c_pid,
            ct.cast(None, ct.POINTER(bcc_symbol_option)),
            ct.byref(sym),
        ) < 0:
            raise Exception("could not determine address of symbol %s in %s"
                            % (symname.decode(), module.decode()))
        new_addr = sym.offset + sym_off
        module_path = ct.cast(sym.module, ct.c_char_p).value
        lib.bcc_procutils_free(sym.module)
        return module_path, new_addr

    @staticmethod
    def find_library(libname, pid=0):
        """
        Find the full path to the shared library whose name starts with "lib{libname}".

        If non-zero pid is given, search only the shared libraries mapped by the process with this pid.
        Otherwise, search the global ldconfig cache at /etc/ld.so.cache.

        Examples:
            BPF.find_library(b"c", pid=12345)  # returns b"/usr/lib/x86_64-linux-gnu/libc.so.6"
            BPF.find_library(b"pthread")       # returns b"/lib/x86_64-linux-gnu/libpthread.so.0"
            BPF.find_library(b"nonexistent")   # returns None
        """
        libname = _assert_is_bytes(libname)
        if pid:
            res = lib.bcc_procutils_which_so_in_process(libname, pid)
        else:
            res = lib.bcc_procutils_which_so(libname, 0)
        if not res:
            return None
        libpath = ct.cast(res, ct.c_char_p).value
        lib.bcc_procutils_free(res)
        return libpath

    @staticmethod
    def get_tracepoints(tp_re):
        results = []
        events_dir = os.path.join(TRACEFS, "events")
        for category in os.listdir(events_dir):
            cat_dir = os.path.join(events_dir, category)
            if not os.path.isdir(cat_dir):
                continue
            for event in os.listdir(cat_dir):
                evt_dir = os.path.join(cat_dir, event)
                if os.path.isdir(evt_dir):
                    tp = ("%s:%s" % (category, event))
                    if re.match(tp_re.decode(), tp):
                        results.append(tp.encode())
        return results

    @staticmethod
    def tracepoint_exists(category, event):
        evt_dir = os.path.join(TRACEFS, "events", category, event)
        return os.path.isdir(evt_dir)

    def attach_tracepoint(self, tp=b"", tp_re=b"", fn_name=b""):
        """attach_tracepoint(tp="", tp_re="", fn_name="")

        Run the bpf function denoted by fn_name every time the kernel tracepoint
        specified by 'tp' is hit. The optional parameters pid, cpu, and group_fd
        can be used to filter the probe. The tracepoint specification is simply
        the tracepoint category and the tracepoint name, separated by a colon.
        For example: sched:sched_switch, syscalls:sys_enter_bind, etc.

        Instead of a tracepoint name, a regular expression can be provided in
        tp_re. The program will then attach to tracepoints that match the
        provided regular expression.

        To obtain a list of kernel tracepoints, use the tplist tool or cat the
        file /sys/kernel/debug/tracing/available_events.

        Examples:
            BPF(text).attach_tracepoint(tp="sched:sched_switch", fn_name="on_switch")
            BPF(text).attach_tracepoint(tp_re="sched:.*", fn_name="on_switch")
        """

        tp = _assert_is_bytes(tp)
        tp_re = _assert_is_bytes(tp_re)
        fn_name = _assert_is_bytes(fn_name)
        if tp_re:
            for tp in BPF.get_tracepoints(tp_re):
                self.attach_tracepoint(tp=tp, fn_name=fn_name)
            return

        fn = self.load_func(fn_name, BPF.TRACEPOINT)
        (tp_category, tp_name) = tp.split(b':')
        fd = lib.bpf_attach_tracepoint(fn.fd, tp_category, tp_name)
        if fd < 0:
            raise Exception("Failed to attach BPF program %s to tracepoint %s" %
                            (fn_name, tp))
        self.tracepoint_fds[tp] = fd
        return self

    def attach_raw_tracepoint(self, tp=b"", fn_name=b""):
        """attach_raw_tracepoint(self, tp=b"", fn_name=b"")

        Run the bpf function denoted by fn_name every time the kernel tracepoint
        specified by 'tp' is hit. The bpf function should be loaded as a
        RAW_TRACEPOINT type. The fn_name is the kernel tracepoint name,
        e.g., sched_switch, sys_enter_bind, etc.

        Examples:
            BPF(text).attach_raw_tracepoint(tp="sched_switch", fn_name="on_switch")
        """

        tp = _assert_is_bytes(tp)
        if tp in self.raw_tracepoint_fds:
            raise Exception("Raw tracepoint %s has been attached" % tp)

        fn_name = _assert_is_bytes(fn_name)
        fn = self.load_func(fn_name, BPF.RAW_TRACEPOINT)
        fd = lib.bpf_attach_raw_tracepoint(fn.fd, tp)
        if fd < 0:
            raise Exception("Failed to attach BPF to raw tracepoint")
        self.raw_tracepoint_fds[tp] = fd
        return self

    def detach_raw_tracepoint(self, tp=b""):
        """detach_raw_tracepoint(tp="")

        Stop running the bpf function that is attached to the kernel tracepoint
        specified by 'tp'.

        Example: bpf.detach_raw_tracepoint("sched_switch")
        """

        tp = _assert_is_bytes(tp)
        if tp not in self.raw_tracepoint_fds:
            raise Exception("Raw tracepoint %s is not attached" % tp)
        os.close(self.raw_tracepoint_fds[tp])
        del self.raw_tracepoint_fds[tp]

    @staticmethod
    def add_prefix(prefix, name):
        if not name.startswith(prefix):
            name = prefix + name
        return name

    @staticmethod
    def support_kfunc():
        # there's no trampoline support for other than x86_64 arch
        if platform.machine() != 'x86_64':
            return False
        if not lib.bpf_has_kernel_btf():
            return False
        # kernel symbol "bpf_trampoline_link_prog" indicates kfunc support
        if BPF.ksymname("bpf_trampoline_link_prog") != -1:
            return True
        return False

    @staticmethod
    def support_lsm():
        if not lib.bpf_has_kernel_btf():
            return False
        # kernel symbol "bpf_lsm_bpf" indicates BPF LSM support
        if BPF.ksymname(b"bpf_lsm_bpf") != -1:
            return True
        return False

    def detach_kfunc(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"kfunc__", fn_name)

        if fn_name not in self.kfunc_entry_fds:
            raise Exception("Kernel entry func %s is not attached" % fn_name)
        os.close(self.kfunc_entry_fds[fn_name])
        del self.kfunc_entry_fds[fn_name]

    def detach_kretfunc(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"kretfunc__", fn_name)

        if fn_name not in self.kfunc_exit_fds:
            raise Exception("Kernel exit func %s is not attached" % fn_name)
        os.close(self.kfunc_exit_fds[fn_name])
        del self.kfunc_exit_fds[fn_name]

    def attach_kfunc(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"kfunc__", fn_name)

        if fn_name in self.kfunc_entry_fds:
            raise Exception("Kernel entry func %s has been attached" % fn_name)

        fn = self.load_func(fn_name, BPF.TRACING)
        fd = lib.bpf_attach_kfunc(fn.fd)
        if fd < 0:
            raise Exception("Failed to attach BPF to entry kernel func")
        self.kfunc_entry_fds[fn_name] = fd
        return self

    def attach_kretfunc(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"kretfunc__", fn_name)

        if fn_name in self.kfunc_exit_fds:
            raise Exception("Kernel exit func %s has been attached" % fn_name)

        fn = self.load_func(fn_name, BPF.TRACING)
        fd = lib.bpf_attach_kfunc(fn.fd)
        if fd < 0:
            raise Exception("Failed to attach BPF to exit kernel func")
        self.kfunc_exit_fds[fn_name] = fd
        return self

    def detach_lsm(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"lsm__", fn_name)

        if fn_name not in self.lsm_fds:
            raise Exception("LSM %s is not attached" % fn_name)
        os.close(self.lsm_fds[fn_name])
        del self.lsm_fds[fn_name]

    def attach_lsm(self, fn_name=b""):
        fn_name = _assert_is_bytes(fn_name)
        fn_name = BPF.add_prefix(b"lsm__", fn_name)

        if fn_name in self.lsm_fds:
            raise Exception("LSM %s has been attached" % fn_name)

        fn = self.load_func(fn_name, BPF.LSM)
        fd = lib.bpf_attach_lsm(fn.fd)
        if fd < 0:
            raise Exception("Failed to attach LSM")
        self.lsm_fds[fn_name] = fd
        return self

    @staticmethod
    def support_raw_tracepoint():
        # kernel symbol "bpf_find_raw_tracepoint" indicates raw_tracepoint support
        if BPF.ksymname("bpf_find_raw_tracepoint") != -1 or \
           BPF.ksymname("bpf_get_raw_tracepoint") != -1:
            return True
        return False

    @staticmethod
    def support_raw_tracepoint_in_module():
        # kernel symbol "bpf_trace_modules" indicates raw tp support in modules, ref: kernel commit a38d1107
        kallsyms = "/proc/kallsyms"
        with open(kallsyms) as syms:
            for line in syms:
                (_, _, name) = line.rstrip().split(" ", 2)
                name = name.split("\t")[0]
                if name == "bpf_trace_modules":
                    return True
            return False

    @staticmethod
    def kernel_struct_has_field(struct_name, field_name):
        struct_name = _assert_is_bytes(struct_name)
        field_name = _assert_is_bytes(field_name)
        return lib.kernel_struct_has_field(struct_name, field_name)

    def detach_tracepoint(self, tp=b""):
        """detach_tracepoint(tp="")

        Stop running a bpf function that is attached to the kernel tracepoint
        specified by 'tp'.

        Example: bpf.detach_tracepoint("sched:sched_switch")
        """

        tp = _assert_is_bytes(tp)
        if tp not in self.tracepoint_fds:
            raise Exception("Tracepoint %s is not attached" % tp)
        res = lib.bpf_close_perf_event_fd(self.tracepoint_fds[tp])
        if res < 0:
            raise Exception("Failed to detach BPF from tracepoint")
        (tp_category, tp_name) = tp.split(b':')
        res = lib.bpf_detach_tracepoint(tp_category, tp_name)
        if res < 0:
            raise Exception("Failed to detach BPF from tracepoint")
        del self.tracepoint_fds[tp]

    def _attach_perf_event(self, progfd, ev_type, ev_config,
            sample_period, sample_freq, pid, cpu, group_fd):
        res = lib.bpf_attach_perf_event(progfd, ev_type, ev_config,
                sample_period, sample_freq, pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to perf event")
        return res

    def attach_perf_event(self, ev_type=-1, ev_config=-1, fn_name=b"",
            sample_period=0, sample_freq=0, pid=-1, cpu=-1, group_fd=-1):
        fn_name = _assert_is_bytes(fn_name)
        fn = self.load_func(fn_name, BPF.PERF_EVENT)
        res = {}
        if cpu >= 0:
            res[cpu] = self._attach_perf_event(fn.fd, ev_type, ev_config,
                    sample_period, sample_freq, pid, cpu, group_fd)
        else:
            for i in get_online_cpus():
                res[i] = self._attach_perf_event(fn.fd, ev_type, ev_config,
                        sample_period, sample_freq, pid, i, group_fd)
        self.open_perf_events[(ev_type, ev_config)] = res

    def _attach_perf_event_raw(self, progfd, attr, pid, cpu, group_fd):
        res = lib.bpf_attach_perf_event_raw(progfd, ct.byref(attr), pid,
                cpu, group_fd, 0)
        if res < 0:
            raise Exception("Failed to attach BPF to perf raw event")
        return res

    def attach_perf_event_raw(self, attr=-1, fn_name=b"", pid=-1, cpu=-1, group_fd=-1):
        fn_name = _assert_is_bytes(fn_name)
        fn = self.load_func(fn_name, BPF.PERF_EVENT)
        res = {}
        if cpu >= 0:
            res[cpu] = self._attach_perf_event_raw(fn.fd, attr,
                    pid, cpu, group_fd)
        else:
            for i in get_online_cpus():
                res[i] = self._attach_perf_event_raw(fn.fd, attr,
                        pid, i, group_fd)
        self.open_perf_events[(attr.type, attr.config)] = res

    def detach_perf_event(self, ev_type=-1, ev_config=-1):
        try:
            fds = self.open_perf_events[(ev_type, ev_config)]
        except KeyError:
            raise Exception("Perf event type {} config {} not attached".format(
                ev_type, ev_config))

        res = 0
        for fd in fds.values():
            res = lib.bpf_close_perf_event_fd(fd) or res
        if res != 0:
            raise Exception("Failed to detach BPF from perf event")
        del self.open_perf_events[(ev_type, ev_config)]

    @staticmethod
    def get_user_functions(name, sym_re):
        return set([name for (name, _) in
                    BPF.get_user_functions_and_addresses(name, sym_re)])

    @staticmethod
    def get_user_addresses(name, sym_re):
        """
        We are returning addresses here instead of symbol names because it
        turns out that the same name may appear multiple times with different
        addresses, and the same address may appear multiple times with the same
        name. We can't attach a uprobe to the same address more than once, so
        it makes sense to return the unique set of addresses that are mapped to
        a symbol that matches the provided regular expression.
        """
        return set([address for (_, address) in
                    BPF.get_user_functions_and_addresses(name, sym_re)])

    @staticmethod
    def get_user_functions_and_addresses(name, sym_re):
        name = _assert_is_bytes(name)
        sym_re = _assert_is_bytes(sym_re)
        addresses = []
        def sym_cb(sym_name, addr):
            dname = sym_name
            if re.match(sym_re, dname):
                addresses.append((dname, addr))
            return 0

        res = lib.bcc_foreach_function_symbol(name, _SYM_CB_TYPE(sym_cb))
        if res < 0:
            raise Exception("Error %d enumerating symbols in %s" % (res, name))
        return addresses

    def _get_uprobe_evname(self, prefix, path, addr, pid):
        if pid == -1:
            return b"%s_%s_0x%x" % (prefix, self._probe_repl.sub(b"_", path), addr)
        else:
            # if pid is valid, put pid in the name, so different pid
            # can have different event names
            return b"%s_%s_0x%x_%d" % (prefix, self._probe_repl.sub(b"_", path), addr, pid)

    def attach_uprobe(self, name=b"", sym=b"", sym_re=b"", addr=None,
            fn_name=b"", pid=-1, sym_off=0):
        """attach_uprobe(name="", sym="", sym_re="", addr=None, fn_name=""
                         pid=-1, sym_off=0)

        Run the bpf function denoted by fn_name every time the symbol sym in
        the library or binary 'name' is encountered. Optional parameters pid,
        cpu, and group_fd can be used to filter the probe.

        If sym_off is given, attach uprobe to offset within the symbol.

        The real address addr may be supplied in place of sym, in which case sym
        must be set to its default value. If the file is a non-PIE executable,
        addr must be a virtual address, otherwise it must be an offset relative
        to the file load address.

        Instead of a symbol name, a regular expression can be provided in
        sym_re. The uprobe will then attach to symbols that match the provided
        regular expression.

        Libraries can be given in the name argument without the lib prefix, or
        with the full path (/usr/lib/...). Binaries can be given only with the
        full path (/bin/sh). If a PID is given, the uprobe will attach to the
        version of the library used by the process.

        Example: BPF(text).attach_uprobe("c", "malloc")
                 BPF(text).attach_uprobe("/usr/bin/python", "main")
        """

        assert sym_off >= 0
        if addr is not None:
            assert sym_off == 0, "offset with addr is not supported"

        name = _assert_is_bytes(name)
        sym = _assert_is_bytes(sym)
        sym_re = _assert_is_bytes(sym_re)
        fn_name = _assert_is_bytes(fn_name)

        if sym_re:
            addresses = BPF.get_user_addresses(name, sym_re)
            self._check_probe_quota(len(addresses))
            for sym_addr in addresses:
                self.attach_uprobe(name=name, addr=sym_addr,
                                   fn_name=fn_name, pid=pid)
            return

        (path, addr) = BPF._check_path_symbol(name, sym, addr, pid, sym_off)

        self._check_probe_quota(1)
        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = self._get_uprobe_evname(b"p", path, addr, pid)
        fd = lib.bpf_attach_uprobe(fn.fd, 0, ev_name, path, addr, pid)
        if fd < 0:
            raise Exception("Failed to attach BPF to uprobe")
        self._add_uprobe_fd(ev_name, fd)
        return self

    def attach_uretprobe(self, name=b"", sym=b"", sym_re=b"", addr=None,
            fn_name=b"", pid=-1):
        """attach_uretprobe(name="", sym="", sym_re="", addr=None, fn_name=""
                            pid=-1)

        Run the bpf function denoted by fn_name every time the symbol sym in
        the library or binary 'name' finishes execution. See attach_uprobe for
        meaning of additional parameters.
        """

        name = _assert_is_bytes(name)
        sym = _assert_is_bytes(sym)
        sym_re = _assert_is_bytes(sym_re)
        fn_name = _assert_is_bytes(fn_name)

        if sym_re:
            for sym_addr in BPF.get_user_addresses(name, sym_re):
                self.attach_uretprobe(name=name, addr=sym_addr,
                                      fn_name=fn_name, pid=pid)
            return

        (path, addr) = BPF._check_path_symbol(name, sym, addr, pid)

        self._check_probe_quota(1)
        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = self._get_uprobe_evname(b"r", path, addr, pid)
        fd = lib.bpf_attach_uprobe(fn.fd, 1, ev_name, path, addr, pid)
        if fd < 0:
            raise Exception("Failed to attach BPF to uretprobe")
        self._add_uprobe_fd(ev_name, fd)
        return self

    def detach_uprobe_event(self, ev_name):
        if ev_name not in self.uprobe_fds:
            raise Exception("Uprobe %s is not attached" % ev_name)
        res = lib.bpf_close_perf_event_fd(self.uprobe_fds[ev_name])
        if res < 0:
            raise Exception("Failed to detach BPF from uprobe")
        res = lib.bpf_detach_uprobe(ev_name)
        if res < 0:
            raise Exception("Failed to detach BPF from uprobe")
        self._del_uprobe_fd(ev_name)

    def detach_uprobe(self, name=b"", sym=b"", addr=None, pid=-1, sym_off=0):
        """detach_uprobe(name="", sym="", addr=None, pid=-1)

        Stop running a bpf function that is attached to symbol 'sym' in library
        or binary 'name'.
        """

        name = _assert_is_bytes(name)
        sym = _assert_is_bytes(sym)
        (path, addr) = BPF._check_path_symbol(name, sym, addr, pid, sym_off)
        ev_name = self._get_uprobe_evname(b"p", path, addr, pid)
        self.detach_uprobe_event(ev_name)

    def detach_uretprobe(self, name=b"", sym=b"", addr=None, pid=-1):
        """detach_uretprobe(name="", sym="", addr=None, pid=-1)

        Stop running a bpf function that is attached to symbol 'sym' in library
        or binary 'name'.
        """

        name = _assert_is_bytes(name)
        sym = _assert_is_bytes(sym)

        (path, addr) = BPF._check_path_symbol(name, sym, addr, pid)
        ev_name = self._get_uprobe_evname(b"r", path, addr, pid)
        self.detach_uprobe_event(ev_name)

    def _trace_autoload(self):
        for i in range(0, lib.bpf_num_functions(self.module)):
            func_name = lib.bpf_function_name(self.module, i)
            if func_name.startswith(b"kprobe__"):
                fn = self.load_func(func_name, BPF.KPROBE)
                self.attach_kprobe(
                    event=self.fix_syscall_fnname(func_name[8:]),
                    fn_name=fn.name)
            elif func_name.startswith(b"kretprobe__"):
                fn = self.load_func(func_name, BPF.KPROBE)
                self.attach_kretprobe(
                    event=self.fix_syscall_fnname(func_name[11:]),
                    fn_name=fn.name)
            elif func_name.startswith(b"tracepoint__"):
                fn = self.load_func(func_name, BPF.TRACEPOINT)
                tp = fn.name[len(b"tracepoint__"):].replace(b"__", b":")
                self.attach_tracepoint(tp=tp, fn_name=fn.name)
            elif func_name.startswith(b"raw_tracepoint__"):
                fn = self.load_func(func_name, BPF.RAW_TRACEPOINT)
                tp = fn.name[len(b"raw_tracepoint__"):]
                self.attach_raw_tracepoint(tp=tp, fn_name=fn.name)
            elif func_name.startswith(b"kfunc__"):
                self.attach_kfunc(fn_name=func_name)
            elif func_name.startswith(b"kretfunc__"):
                self.attach_kretfunc(fn_name=func_name)
            elif func_name.startswith(b"lsm__"):
                self.attach_lsm(fn_name=func_name)

    def trace_open(self, nonblocking=False):
        """trace_open(nonblocking=False)

        Open the trace_pipe if not already open
        """
        if not self.tracefile:
            self.tracefile = open("%s/trace_pipe" % TRACEFS, "rb")
            if nonblocking:
                fd = self.tracefile.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return self.tracefile

    def trace_fields(self, nonblocking=False):
        """trace_fields(nonblocking=False)

        Read from the kernel debug trace pipe and return a tuple of the
        fields (task, pid, cpu, flags, timestamp, msg) or None if no
        line was read (nonblocking=True)
        """
        while True:
            line = self.trace_readline(nonblocking)
            if not line and nonblocking: return (None,) * 6
            # don't print messages related to lost events
            if line.startswith(b"CPU:"): continue
            task = line[:16].lstrip()
            line = line[17:]
            ts_end = line.find(b":")
            try:
                pid, cpu, flags, ts = line[:ts_end].split()
            except Exception as e:
                continue
            cpu = cpu[1:-1]
            # line[ts_end:] will have ": [sym_or_addr]: msgs"
            # For trace_pipe debug output, the addr typically
            # is invalid (e.g., 0x1). For kernel 4.12 or earlier,
            # if address is not able to match a kernel symbol,
            # nothing will be printed out. For kernel 4.13 and later,
            # however, the illegal address will be printed out.
            # Hence, both cases are handled here.
            line = line[ts_end + 1:]
            sym_end = line.find(b":")
            msg = line[sym_end + 2:]
            try:
                return (task, int(pid), int(cpu), flags, float(ts), msg)
            except Exception as e:
                return ("Unknown", 0, 0, "Unknown", 0.0, "Unknown")

    def trace_readline(self, nonblocking=False):
        """trace_readline(nonblocking=False)

        Read from the kernel debug trace pipe and return one line
        If nonblocking is False, this will block until ctrl-C is pressed.
        """

        trace = self.trace_open(nonblocking)

        line = None
        try:
            line = trace.readline(1024).rstrip()
        except IOError:
            pass
        return line

    def trace_print(self, fmt=None):
        """trace_print(self, fmt=None)

        Read from the kernel debug trace pipe and print on stdout.
        If fmt is specified, apply as a format string to the output. See
        trace_fields for the members of the tuple
        example: trace_print(fmt="pid {1}, msg = {5}")
        """

        while True:
            if fmt:
                fields = self.trace_fields(nonblocking=False)
                if not fields: continue
                line = fmt.format(*fields)
            else:
                line = self.trace_readline(nonblocking=False)
            print(line)
            sys.stdout.flush()

    @staticmethod
    def _sym_cache(pid):
        """_sym_cache(pid)

        Returns a symbol cache for the specified PID.
        The kernel symbol cache is accessed by providing any PID less than zero.
        """
        if pid < 0 and pid != -1:
            pid = -1
        if not pid in BPF._sym_caches:
            BPF._sym_caches[pid] = SymbolCache(pid)
        return BPF._sym_caches[pid]

    @staticmethod
    def sym(addr, pid, show_module=False, show_offset=False, demangle=True):
        """sym(addr, pid, show_module=False, show_offset=False)

        Translate a memory address into a function name for a pid, which is
        returned. When show_module is True, the module name is also included.
        When show_offset is True, the instruction offset as a hexadecimal
        number is also included in the string.

        A pid of less than zero will access the kernel symbol cache.

        Example output when both show_module and show_offset are True:
            "start_thread+0x202 [libpthread-2.24.so]"

        Example output when both show_module and show_offset are False:
            "start_thread"
        """

        #addr is of type stacktrace_build_id
        #so invoke the bsym address resolver
        typeofaddr = str(type(addr))
        if typeofaddr.find('bpf_stack_build_id') != -1:
          sym = bcc_symbol()
          b = bcc_stacktrace_build_id()
          b.status = addr.status
          b.build_id = addr.build_id
          b.u.offset = addr.offset
          res = lib.bcc_buildsymcache_resolve(BPF._bsymcache,
                                              ct.byref(b),
                                              ct.byref(sym))
          if res < 0:
            if sym.module and sym.offset:
              name,offset,module = (None, sym.offset,
                        ct.cast(sym.module, ct.c_char_p).value)
            else:
              name, offset, module = (None, addr, None)
          else:
            name, offset, module = (sym.name, sym.offset,
                                    ct.cast(sym.module, ct.c_char_p).value)
        else:
          name, offset, module = BPF._sym_cache(pid).resolve(addr, demangle)

        offset = b"+0x%x" % offset if show_offset and name is not None else b""
        name = name or b"[unknown]"
        name = name + offset
        module = b" [%s]" % os.path.basename(module) \
            if show_module and module is not None else b""
        return name + module

    @staticmethod
    def ksym(addr, show_module=False, show_offset=False):
        """ksym(addr)

        Translate a kernel memory address into a kernel function name, which is
        returned. When show_module is True, the module name ("kernel") is also
        included. When show_offset is true, the instruction offset as a
        hexadecimal number is also included in the string.

        Example output when both show_module and show_offset are True:
            "default_idle+0x0 [kernel]"
        """
        return BPF.sym(addr, -1, show_module, show_offset, False)

    @staticmethod
    def ksymname(name):
        """ksymname(name)

        Translate a kernel name into an address. This is the reverse of
        ksym. Returns -1 when the function name is unknown."""
        return BPF._sym_cache(-1).resolve_name(None, name)

    def num_open_kprobes(self):
        """num_open_kprobes()

        Get the number of open K[ret]probes. Can be useful for scenarios where
        event_re is used while attaching and detaching probes.
        """
        return len(self.kprobe_fds)

    def num_open_uprobes(self):
        """num_open_uprobes()

        Get the number of open U[ret]probes.
        """
        return len(self.uprobe_fds)

    def num_open_tracepoints(self):
        """num_open_tracepoints()

        Get the number of open tracepoints.
        """
        return len(self.tracepoint_fds)

    def perf_buffer_poll(self, timeout = -1):
        """perf_buffer_poll(self)

        Poll from all open perf ring buffers, calling the callback that was
        provided when calling open_perf_buffer for each entry.
        """
        readers = (ct.c_void_p * len(self.perf_buffers))()
        for i, v in enumerate(self.perf_buffers.values()):
            readers[i] = v
        lib.perf_reader_poll(len(readers), readers, timeout)

    def perf_buffer_consume(self):
        """perf_buffer_consume(self)

        Consume all open perf buffers, regardless of whether or not
        they currently contain events data. Necessary to catch 'remainder'
        events when wakeup_events > 1 is set in open_perf_buffer
        """
        readers = (ct.c_void_p * len(self.perf_buffers))()
        for i, v in enumerate(self.perf_buffers.values()):
            readers[i] = v
        lib.perf_reader_consume(len(readers), readers)

    def kprobe_poll(self, timeout = -1):
        """kprobe_poll(self)

        Deprecated. Use perf_buffer_poll instead.
        """
        self.perf_buffer_poll(timeout)

    def _open_ring_buffer(self, map_fd, fn, ctx=None):
        if not self._ringbuf_manager:
            self._ringbuf_manager = lib.bpf_new_ringbuf(map_fd, fn, ctx)
            if not self._ringbuf_manager:
                raise Exception("Could not open ring buffer")
        else:
            ret = lib.bpf_add_ringbuf(self._ringbuf_manager, map_fd, fn, ctx)
            if ret < 0:
                raise Exception("Could not open ring buffer")

    def ring_buffer_poll(self, timeout = -1):
        """ring_buffer_poll(self)

        Poll from all open ringbuf buffers, calling the callback that was
        provided when calling open_ring_buffer for each entry.
        """
        if not self._ringbuf_manager:
            raise Exception("No ring buffers to poll")
        lib.bpf_poll_ringbuf(self._ringbuf_manager, timeout)

    def ring_buffer_consume(self):
        """ring_buffer_consume(self)

        Consume all open ringbuf buffers, regardless of whether or not
        they currently contain events data. This is best for use cases
        where low latency is desired, but it can impact performance.
        If you are unsure, use ring_buffer_poll instead.
        """
        if not self._ringbuf_manager:
            raise Exception("No ring buffers to poll")
        lib.bpf_consume_ringbuf(self._ringbuf_manager)

    def free_bcc_memory(self):
        return lib.bcc_free_memory()

    @staticmethod
    def add_module(modname):
      """add_module(modname)

        Add a library or exe to buildsym cache
      """
      try:
        lib.bcc_buildsymcache_add_module(BPF._bsymcache, modname.encode())
      except Exception as e:
        print("Error adding module to build sym cache"+str(e))

    def donothing(self):
        """the do nothing exit handler"""


    def close(self):
        """close(self)

        Closes all associated files descriptors. Attached BPF programs are not
        detached.
        """
        for name, fn in list(self.funcs.items()):
            os.close(fn.fd)
            del self.funcs[name]
        if self.module:
            lib.bpf_module_destroy(self.module)
            self.module = None

    def cleanup(self):
        # Clean up opened probes
        for k, v in list(self.kprobe_fds.items()):
            self.detach_kprobe_event(k)
        for k, v in list(self.uprobe_fds.items()):
            self.detach_uprobe_event(k)
        for k, v in list(self.tracepoint_fds.items()):
            self.detach_tracepoint(k)
        for k, v in list(self.raw_tracepoint_fds.items()):
            self.detach_raw_tracepoint(k)
        for k, v in list(self.kfunc_entry_fds.items()):
            self.detach_kfunc(k)
        for k, v in list(self.kfunc_exit_fds.items()):
            self.detach_kretfunc(k)
        for k, v in list(self.lsm_fds.items()):
            self.detach_lsm(k)

        # Clean up opened perf ring buffer and perf events
        table_keys = list(self.tables.keys())
        for key in table_keys:
            if isinstance(self.tables[key], PerfEventArray):
                del self.tables[key]
        for (ev_type, ev_config) in list(self.open_perf_events.keys()):
            self.detach_perf_event(ev_type, ev_config)
        if self.tracefile:
            self.tracefile.close()
            self.tracefile = None

        self.close()

        # Clean up ringbuf
        if self._ringbuf_manager:
            lib.bpf_free_ringbuf(self._ringbuf_manager)
            self._ringbuf_manager = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
