#!/usr/bin/env python3.6 this-is-for-pylint
# pylint: disable=no-absolute-import
#
# Copyright (c) 2021, Hudson River Trading LLC.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 21-Apr-2021   Guangyuan Yang       created this.

"""
topclass is a shared library to create top-like eBPF utilities. You need
to inherit TopClass and implement/rewrite all required methods.
---
Usage:
from topclass import TopClass

class FileTop(TopClass):
    ...

filetop = FileTop()
filetop.run()
"""


import abc
import argparse
import curses
import json
import sys
import time


class CustomFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter,
):
    """
    A multiple inheritance approach to subclass both HelpFormatter's, in
    order to print argument defaults and raw description/epilog.
    """


class Printer:  # pylint: disable=too-many-instance-attributes
    """
    A class to keep track of currently enabled data columns, and produce
    formatted output based on definitions in column_fmt. If passed in
    stdscr, it will instead use this curses screen for output and print
    additional info (header, footer) and handle refreshes.

    User must call self.reset_all() for a window refresh.
    """

    def __init__(self, column_fmt: dict, app_name: str, args, stdscr=None):
        """
        If stdscr is passed in, the class will use curses for output.
        """
        self._column_fmt = column_fmt
        self._stdscr = stdscr
        self._args = args
        self._app_name = app_name
        self._columns = []
        self._row_data = []
        self._json_metadata = {}

        # to be populated by TopClass.log_end_ts(), see definitions there
        self.last_true_interval = None

        # add header info to first row
        self.add_row_data({k: k.upper() for k in self._column_fmt})

        if self._stdscr:
            # get the window size
            self._height, self._width = self._stdscr.getmaxyx()

            # clear screen and print info lines
            self._stdscr.clear()
            self.print_loadavg_line()
            self.print_status_line()
            self._stdscr.refresh()

        # validate json meta pairs and populate self._json_metadata accordingly
        if self._args.json_add_meta:
            for m in self._args.json_add_meta:
                parts = m.split("=", 1)
                if len(parts) != 2:
                    raise ValueError("JSON metadata has to be in the form of KEY=VALUE")
                self._json_metadata[parts[0]] = parts[1]

    def add_col(self, *args):
        self._columns += args

    def add_row_data(self, row_dict: dict):
        self._row_data.append(row_dict)

    def print_status_line(self):
        """
        The status line lives in the last line of the screen.
        """
        if self._stdscr:
            status = "Tracing... "
            if self.last_true_interval:
                status += f"Last duration is {self.last_true_interval:.6f} secs "
                status += f"({self._args.interval} secs set). "
            else:
                status += f"Interval is set to {self._args.interval} secs. "
            status += "Hit Ctrl-C to end."
            self._stdscr.addnstr(
                self._height - 1,
                0,
                "{s:<{w}}".format(
                    s=status,
                    w=self._width - 1,  # fill the whole line
                ),
                self._width - 1,
                curses.A_REVERSE,
            )

    def print_loadavg_line(self):
        """
        The loadavg line lives in the first line of the screen.
        """
        ts = time.strftime("%H:%M:%S")

        with open("/proc/loadavg") as stats:
            self._stdscr.addnstr(
                0,
                0,
                f"{self._app_name} - {ts} loadavg: {stats.read()}",
                self._width - 1,
            )

    def flush_all(self):
        """
        Print everything as specified by self._columns for the columns
        and self._row_data for the rows, added by self.add_row_data().
        Data will be erased after printing. If using curses, the screen
        is cleared first.
        """
        template = " ".join([self._column_fmt[k] for k in self._columns])

        if self._stdscr:
            # get the window size again in case of resizing
            self._height, self._width = self._stdscr.getmaxyx()

            # clear screen and print info lines
            self._stdscr.clear()
            self.print_loadavg_line()
            self.print_status_line()

            # print header
            self._stdscr.addnstr(
                2,
                0,
                "{s:<{w}}".format(
                    s=template.format(**self._row_data[0]),
                    w=self._width - 1,  # fill the whole line
                ),
                self._width - 1,
                curses.A_REVERSE,
            )

            # print data
            for idx, d in enumerate(self._row_data[1 : self._height - 3]):
                row_str = template.format(**d)
                self._stdscr.addnstr(idx + 3, 0, row_str, self._width - 1)
            self._stdscr.refresh()
        elif self._args.json_lines_output:
            # skip header
            for d in self._row_data[1:]:
                # append additional metadata
                if self._json_metadata:
                    d.update(self._json_metadata)
                print(json.dumps(d))
        else:
            for d in self._row_data:
                row_str = template.format(**d)
                print(row_str)

        # clean up and add header info to first row
        self._columns = []
        self._row_data = []
        self.add_row_data({k: k.upper() for k in self._column_fmt})


class TopClass:  # pylint: disable=too-many-instance-attributes
    """
    A base class to be used by *top utilities.

    Use self.run() as the entry point as it will handle the text/screen
    modes automatically based on self.args.interactive and
    self.args.noclear.

    Child class should implement:
    - attach_kprobes()
    - output()
    """

    def __init__(
        self,
        app_name: str,
        bpf_table: str,
        desc: str,
        epilog: str,
        column_fmt: dict,
        __metaclass__=abc.ABCMeta,
    ):
        """
        Child classes need to extend this, and populate self.args by
        calling self.arg_parser.parse_args().
        """
        self.app_name = app_name
        self.column_fmt = column_fmt
        self.bpf_table = bpf_table

        # to be initialized by self._run()
        self.printer = None

        # to be populated by self.log_end_ts() called by
        # self.top_output(), used to calculate the true interval
        self.last_start_ts = None
        self.last_end_ts = None
        self.last_true_interval = None

        self.arg_parser = argparse.ArgumentParser(
            description=desc,
            epilog=epilog,
            formatter_class=CustomFormatter,
        )

        # common arguments
        self.arg_parser.add_argument(
            "interval",
            type=int,
            nargs="?",
            default=3,
            help="output interval in seconds",
        )

        # interactive arguments
        self.arg_parser.add_argument(
            "-i",
            "--interactive",
            action="store_true",
            help="run in a loop until interrupted",
        )
        self.arg_parser.add_argument(
            "-C", "--noclear", action="store_true", help="don't clear the screen"
        )
        self.arg_parser.add_argument(
            "-r", "--maxrows", type=int, help="maximum rows to print, default unlimited"
        )

        # non-interactive arguments
        self.arg_parser.add_argument(
            "--json",
            action="store_true",
            dest="json_lines_output",
            help="prints the data in JSON lines format",
        )
        self.arg_parser.add_argument(
            "--json-add-meta",
            action="append",
            dest="json_add_meta",
            help="additional metadata attached to each JSON object. Format: "
            "KEY=VALUE, and can be supplied multiple times",
        )

        # debug arguments
        self.arg_parser.add_argument(
            "--dry-run",
            action="store_true",
            help="print out the generated eBPF code and exit",
        )

        # this is populated by child classes in self.__init__()
        self.args = None

        # this is populated by child classes in self.attach_kprobes()
        self.bpf = None

    @abc.abstractmethod
    def attach_kprobes(self):
        """
        Implement necessary code generation, and attach kprobes.

        Child classes need to populate self.bpf: bcc.BPF.
        Child classes need to implement dry_run option before attaching.
        """
        return NotImplementedError

    def log_start_ts(self):
        """
        Log self.last_start_ts.
        """
        self.last_start_ts = time.time()

    def log_end_ts(self):
        """
        Log self.last_end_ts, and if both timestamps exist, calculate
        self.last_true_interval and store a copy in self.printer for
        status line printing.
        """
        self.last_end_ts = time.time()
        if self.last_start_ts:
            true_interval = self.last_end_ts - self.last_start_ts
            self.last_true_interval = true_interval
            # used for printing the status line
            self.printer.last_true_interval = true_interval

    def top_output(self):
        """
        A runner that continuously refreshes and runs the output
        program, and do necessary cleanup between runs. It also
        registers and keeps the last two timestamps self.last_start_ts
        and self.last_end_ts to derive the "actual" interval of last
        run, so that ops/sec calculation becomes more accurate.
        """
        # flag to exit when interrupted
        exiting = False

        # loop
        while True:
            self.log_start_ts()

            try:
                time.sleep(self.args.interval)
            except KeyboardInterrupt:
                exiting = True

            counts = self.bpf.get_table(self.bpf_table)
            # get the static version
            counts_list = counts.items()

            self.log_end_ts()

            self.output(counts_list)

            if exiting:
                return

            # counts.clear() here could get into a race condition,
            # attached kprobes are still incrementing the counts while
            # clear() is in the process of cleaning up, and this step
            # may never end. Use counts.zero() here instead, which is
            # slightly slower and have slightly different effect
            # (instead of deleting entries, only zeroing the count), but
            # can guarantee to return.
            counts.zero()

    def once_output(self):
        """
        A runner that only runs the output program once and does not do
        any cleanup.
        """
        time.sleep(self.args.interval)
        counts = self.bpf.get_table(self.bpf_table)
        # get the static version
        counts_list = counts.items()
        self.output(counts_list)

    @abc.abstractmethod
    def output(self, counts_list: list):
        """
        Get and print desired output from a snapshot of BPF map,
        implemented by the child class.

        Child classes need to implement self.args.maxrows.
        """
        return NotImplementedError

    def _run(self, stdscr=None):
        """
        Create stdscr, attach kprobe and produce output.
        """
        # set up curses
        if stdscr:
            curses.use_default_colors()  # default background color
            curses.curs_set(0)  # hide cursors in the UI

        # register printer
        self.printer = Printer(
            column_fmt=self.column_fmt,
            app_name=self.app_name,
            args=self.args,
            stdscr=stdscr,
        )

        self.attach_kprobes()
        # top run
        if self.args.interactive:
            self.top_output()
        # run once and exit
        else:
            self.once_output()

    def run(self):
        """
        The entry point that creates stdscr and printer, and run the
        real _run().
        """

        # validate combinations of flags
        if self.args.interactive and self.args.json_lines_output:
            print("The --json option is not applicable to the interactive mode.")
            sys.exit()
        if self.args.json_add_meta and not self.args.json_lines_output:
            print("The --json-add-meta option has to be used with the --json option.")
            sys.exit()

        if self.args.interactive and not self.args.noclear:
            curses.wrapper(self._run)
        else:
            self._run()
