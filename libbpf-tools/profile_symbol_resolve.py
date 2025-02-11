#!/usr/bin/python

import argparse
import re
import subprocess
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from datetime import datetime
from sortedcontainers import SortedDict


class Usyms:
    """
    Usyms.

    A class to manage and manipulate symbol information from dynamic shared
    objects (DSOs).
    """

    def __init__(self):
        """
        Initialize a new Usyms instance.

        Attributes:
            symbols (defaultdict): A dictionary mapping process IDs to
                                   lists of symbol information.
        """
        self.symbols = defaultdict(list)

    def add_symbol(self, path, ranges, pid, range_sz,
                   sh_addr, sh_offset, dso_type):
        """
        Add a symbol entry for a given process ID (pid).

        Args:
            path (str): The path to the dynamic shared object.
            ranges (list): A list of memory ranges associated with the symbol.
            pid (int): The process ID to associate with the symbol.
            range_sz (int): The size of the range.
            sh_addr (int): Section header address.
            sh_offset (int): Section header offset.
            dso_type (str): The type of the dynamic shared object
                            (e.g., EXEC, DYN).
        """
        self.symbols[pid] += [{
            'path': path,
            'ranges': ranges,
            'pid': pid,
            'range_sz': range_sz,
            'sh_addr': sh_addr,
            'sh_offset': sh_offset,
            'type': dso_type,
            'sym_table': SortedDict(),
        }]

    def _load_sym_table_from_elf(self, dso):
        """
        Load the symbol table from the specified ELF file.

        Args:
            dso (dict): A dictionary containing information about the
                        dynamic shared object.
        """
        if not Path(dso['path']).exists():
            return

        try:
            with open(dso['path'], 'rb') as f:
                elf = ELFFile(f)

                # Iterate over sections
                for section in elf.iter_sections():
                    # Check if section type is SYMTAB or DYNSYM
                    if section['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                        self._add_syms(dso, section)
        except FileNotFoundError:
            print(f"File not found: {dso['path']}")
        except OSError as e:
            print(f"OS error while accessing the file: {e}")

    def _add_syms(self, dso, section):
        """Add symbols from an ELF section to the DSO object."""
        if not isinstance(section, SymbolTableSection):
            return

        # Check if the symbol table's size is valid.
        sym_size = section['sh_entsize']
        if sym_size == 0:
            print('Invalid symbol size')
            return

        # Iterate over symbol table entries.
        for symbol in section.iter_symbols():
            name = symbol.name
            sym_value = symbol['st_value']
            sym_size = symbol['st_size']

            # Skip invalid entries, empty names, or zero-valued symbols
            if not name or sym_value == 0 or sym_size == 0:
                continue

            # Add the valid symbol to the DSO's sym_table
            dso['sym_table'][sym_value] = {'name': name,
                                           'size': sym_size,
                                           'offset': 0}

    def _load_sym_table(self, dso):
        if not dso['type'] in ['EXEC', 'DYN']:
            return
        self._load_sym_table_from_elf(dso)

    def _find_sym(self, dso, offset):
        # Convert the ordered dictionary to a list of items for indexed access
        sym_list = list(dso['sym_table'].items())
        start = 0
        end = len(sym_list) - 1

        # Find the largest sym_addr <= offset using binary search
        while start < end:
            mid = start + (end - start + 1) // 2
            sym_addr = sym_list[mid][0]  # Accessing the value of the tuple

            if sym_addr <= offset:
                start = mid
            else:
                end = mid - 1

        if (
            start == end
            and sym_list[start][0]
            <= offset
            < sym_list[start][0] + sym_list[start][1]['size']
        ):
            sym_list[start][1]['offset'] = offset - sym_list[start][0]
            return sym_list[start][1]['name']

        return None

    def _find_dso(self, addr, pid):
        """Find the DSO, by PID, containing the given address,
        returning the DSO and offset of the giving symbol"""
        for dso in self.symbols[pid]:
            for i in range(dso['range_sz']):
                range_item = dso['ranges'][i]
                if not (range_item['start'] < addr < range_item['end']):
                    continue
                if dso['type'] in ['DYN', 'VDSO']:
                    # Offset within the mmap
                    offset = addr - range_item['start'] + range_item['file_off']
                    # Offset within the ELF for dynamic symbol lookup
                    offset += dso['sh_addr'] - dso['sh_offset']
                else:
                    offset = addr

                if not dso['sym_table']:
                    self._load_sym_table(dso)
                return dso, offset

        return None, None

    def map_addr(self, addr, pid):
        """Return the symbol name corresponding to the given address."""
        dso, offset = self._find_dso(addr, pid)
        if not dso:
            return None
        return self._find_sym(dso, offset)

    def __str__(self):
        """Return a human-readable string representation of the Usyms table."""
        output = []
        for dso, data in self.symbols.items():
            ranges_str = ', '.join(
                [
                    f"{{start = {r['start']:#x}, end = {r['end']:#x}, "
                    f"file_off = {r['file_off']:#x}}}"
                    for r in data['ranges']
                ]
            )
            output.append(
                f'dso = "{dso}", ranges = [{ranges_str}], range_sz = {data["range_sz"]}, '
                f'sh_addr = {data["sh_addr"]:#x}, sh_offset = {data["sh_offset"]:#x}, '
                f'type = {data["type"]}, sym_table = {data["sym_table"]}'
            )
        return '\n'.join(output)

    def __repr__(self):
        """Return a formal string representation of the Usyms instance."""
        return f"<Usyms with {len(self.symbols)} symbols>"


def load_usyms(rootfs_path, dsos):
    """Load DSO information from a specified file (inside the provided root fs).

    Args:
        rootfs_path (str): The root fs prefix to compose final DSO paths
        dsos (list of str): The list of DSO information

    Returns: Usyms: An instance of the Usyms class populated with the
        parsed symbols, or None if an error occurred during file
        reading or parsing.
    """
    usyms = Usyms()

    # Patterns for parsing
    pattern = re.compile(
        r'path = "(?P<path>[^"]+)", pid = (?P<pid>\d+), '
        r'ranges = \[(?P<ranges>\{[^\}]+\})\], '
        r'range_sz = (?P<range_sz>\d+), '
        r'sh_addr = (?P<sh_addr>0x[0-9a-f]+), '
        r'sh_offset = (?P<sh_offset>0x[0-9a-f]+), type = (?P<type>[A-Z]+)'
    )

    range_pattern = re.compile(
        r'start = (?P<start>0x[0-9a-f]+), end = (?P<end>0x[0-9a-f]+), '
        r'file_off = (?P<file_off>0x[0-9a-f]+)'
    )

    # Reading and parsing the file
    try:
        for line in dsos:
            match = pattern.match(line.strip())
            if match:
                path = match.group('path')
                ranges_str = match.group('ranges')
                pid = int(match.group('pid'))
                range_sz = int(match.group('range_sz'))
                sh_addr = int(match.group('sh_addr'), 16)
                sh_offset = int(match.group('sh_offset'), 16)
                dso_type = match.group('type')

                ranges = []
                ranges_match = range_pattern.search(ranges_str)
                while ranges_match:
                    ranges.append(
                        {
                            'start': int(ranges_match.group('start'), 16),
                            'end': int(ranges_match.group('end'), 16),
                            'file_off': int(ranges_match.group('file_off'), 16),
                        }
                    )
                    ranges_match = range_pattern.search(
                        ranges_str, ranges_match.end()
                    )

                usyms.add_symbol(
                    rootfs_path + path, ranges, pid, range_sz, sh_addr,
                    sh_offset, dso_type
                )

        return usyms

    except ValueError as e:
        print(f"Value error while parsing: {e}")
        return None


class Ksyms:
    """A class to manage a symbol table for kernel symbols, mapping
    addresses to their corresponding names.

    Attributes:
        symbols (dict): A dictionary mapping memory addresses to symbol names.
    """

    def __init__(self):
        self.symbols = {}

    def add_symbol(self, name, addr):
        """Add a symbol with the given name and address to the symbol table."""
        self.symbols[addr] = name

    def map_addr(self, addr):
        """Return the symbol name corresponding to the given address"""
        candidates = [key for key in self.symbols if key <= addr]
        if not candidates:
            return None
        largest_addr = max(candidates)
        return self.symbols[largest_addr]

    def __str__(self):
        """Return a human-readable string representation of
        the symbol table."""
        output = []
        for addr in sorted(self.symbols.keys()):
            output.append(f"{addr:#x}: {self.symbols[addr]}")
        return '\n'.join(output)

    def __repr__(self):
        """Return a formal string representation of the Ksyms instance."""
        return f"<Ksyms with {len(self.symbols)} symbols>"


def load_ksyms(symbols):
    """Load kernel symbols from a table (/proc/kallsyms format).

    This function reads a kernel symbols file, extracts symbol
    addresses and names, and stores them in an instance of the Ksyms
    class. The file is expected to have each line formatted such that
    the first column is the symbol address (in hexadecimal) and the
    third column is the symbol name.

    Args:
        symbols (str): the list of kernel symbols.

    Returns: Ksyms or None: An instance of the Ksyms class containing
        the loaded symbols, or None if the file does not exist or an
        error occurs during file reading.

    Notes: The function skips any lines that do not contain at least
        three space-separated parts.
    """
    ksyms = Ksyms()
    for line in symbols:
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_addr = int(parts[0], 16)
        sym_name = parts[2]

        ksyms.add_symbol(sym_name, sym_addr)

    return ksyms


def process_lines(ksyms, usyms, stack_traces):
    """Processes stack traces to resolve addresses to their
    corresponding symbol names, using kernel and user symbol tables
    (ksyms and usyms). Outputs a list of resolved stack trace lines.

    Args:
        ksyms (Ksyms): Kernel symbol table for address resolution.
        usyms (Usyms): User space symbol table for address resolution by PID.
        stack_traces (list): List of strings containing stack traces.

    Returns: list: Resolved stack trace lines with addresses mapped to
        their corresponding symbols.
    """
    output, buf = [], []
    pid = None

    def process_buffer(buf, pid):
        """Process buffered lines to map addresses to symbols."""
        for buffered_line in buf:
            addr_match = re.match(r'^(\s+)\[(0x[0-9a-fA-F]+)\]$',
                                  buffered_line)
            if addr_match:
                addr_str = addr_match.group(2)
                leading_whitespace = addr_match.group(1)
                addr = int(addr_str, 16)

                # Determine symbol source based on address range
                symbol = (ksyms.map_addr(addr) if addr >= 0xFFFF000000000000
                          else usyms.map_addr(addr, pid))

                if symbol:
                    output.append(f"{leading_whitespace}{symbol}")
                else:
                    output.append(f"{leading_whitespace}[unknown: {addr_str}]")
            else:
                output.append(buffered_line)

    for line in stack_traces:
        line = line.rstrip()

        pid_match = re.search(r'\((\d+)\)', line)
        if pid_match:
            pid = int(pid_match.group(1))
            process_buffer(buf, pid)
            buf = []
            output.append(line)
        else:
            buf.append(line)

    process_buffer(buf, pid)
    return '\n'.join(output)


def _str2bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in ('true', 'yes', '1'):
        return True
    if value.lower() in ('false', 'no', '0'):
        return False

    raise argparse.ArgumentTypeError('Boolean value expected (true/false).')


def generate_flamegraph(input_content, timestamp, min_percent_show=0.3):
    '''Generates a flamegraph SVG from profiling data using external
    inferno tools.
    '''
    collapse_process = subprocess.Popen(
        ['inferno-collapse-dtrace'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    tmp, _ = collapse_process.communicate(input_content)

    if collapse_process.returncode != 0:
        raise RuntimeError('inferno-collapse-dtrace failed.')

    flamegraph_process = subprocess.Popen(
        ['inferno-flamegraph', f'--minwidth={min_percent_show}',
         f'--title=Profiling flamechart ({timestamp})',
         f'--subtitle=Min. percent shown: {min_percent_show}',
         '--flamechart'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    out_svg_content, _ = flamegraph_process.communicate(tmp)

    if flamegraph_process.returncode != 0:
        raise RuntimeError('inferno-flamegraph failed.')

    return out_svg_content


def main():
    """Main entry point for processing a BCC context file containing
    stack traces, DSO paths, and kernel symbols.  It expects a single
    command-line argument specifying the file path to the BCC context
    file, which can be a tarball-compressed (autodetected).

    The function reads the file and splits its content into stack
    traces, DSO paths, and kernel symbols using a delimiter
    ('=========='). It then loads kernel and user symbol tables,
    processes the stack traces to resolve symbol names, and prints the
    resolved stack traces.

    """
    parser = argparse.ArgumentParser(
        description='Resolve stack trace addresses'
        ' to symbol names, given a lookup mappings'
        ' file and a path to a rootfs with full'
        ' debug symbols. For now, hardcodedly dependent'
        ' on external SVG creation tool \'inferno\'.')

    parser.add_argument('mappings_file_path', type=str,
                        help='Path to the symbol mappings file')
    parser.add_argument('rootfs_path', type=str,
                        help='Path to the root file system with full debugging symbols')
    parser.add_argument('--min-percent', type=float, default=0.3,
                        help='Minimum percentage to show on output flamegraph'
                        ' (default: 0.3, --create-svg=True implied)')
    parser.add_argument('--create-svg', type=_str2bool, nargs='?', const=True,
                        default=True,
                        help='Enable or disable SVG creation'
                        ' (default: True, expects "inferno" tool depedency present).')

    args = parser.parse_args()

    try:
        if tarfile.is_tarfile(args.mappings_file_path):
            with tarfile.open(args.mappings_file_path, 'r:bz2') as tar:
                members = tar.getmembers()
                if not members:
                    print(f"Error: No files found in the tarball {args.mappings_file_path}.")
                    sys.exit(1)
                with tar.extractfile(members[0]) as extracted_file:
                    file_content = extracted_file.read().decode('utf-8')
        else:
            with open(args.mappings_file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()

        timestamp_pattern = r"\d{8}_\d{6}"

        match = re.search(timestamp_pattern, args.mappings_file_path)
        timestamp = None

        if match:
            timestamp = datetime.strptime(match.group(), '%Y%m%d_%H%M%S')
        else:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        stack_traces, dsos, kernel_symbols = \
            (section.split('\n') for section in re.split('==========',
                                                         file_content))

        ksyms, usyms = load_ksyms(kernel_symbols), \
            load_usyms(args.rootfs_path, dsos)

        annotated_flame_graph_input = process_lines(ksyms, usyms, stack_traces)
        if not args.create_svg:
            print(annotated_flame_graph_input)
        else:
            print(generate_flamegraph(annotated_flame_graph_input,
                                      timestamp, args.min_percent))

    except FileNotFoundError:
        print(f'Error: File {args.mappings_file_path} not found.')
    except UnicodeDecodeError:
        print(f'Error: Could not decode the file {args.mappings_file_path}.')
    except ValueError:
        print(f'Error: Unexpected content format in {args.mappings_file_path}.')
    except IOError as e:
        print(f'Error while reading the file {args.mappings_file_path}: {e}')


if __name__ == '__main__':
    main()
