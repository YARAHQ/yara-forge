#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yaraQA - YARA Rule Analyzer
# Florian Roth
#
# IMPORTANT: Requires plyara
#            Do not install plyara via pip
#            Use https://github.com/plyara/plyara

__version__ = "0.8.1"

import os
import sys
import argparse
import logging
import pprint
import platform

from main.core import YaraQA
from main.fileops import readFiles

sys.path.insert(0, os.getcwd())


if __name__ == '__main__':
    # Parse Arguments
    parser = argparse.ArgumentParser(description='YARA RULE ANALYZER')
    parser.add_argument('-f', action='append', nargs='+', help='Path to input files (one or more YARA rules, separated by space)',
                        metavar='yara files')
    parser.add_argument('-d', action='append', nargs='+', help='Path to input directory '
                                                               '(YARA rules folders, separated by space)',
                        metavar='yara files')
    parser.add_argument('-o', help="Output file that lists the issues (JSON, default: 'yaraQA-issues.json')", metavar='outfile', default=r'yaraQA-issues.json')
    parser.add_argument('-b', help='Use a issues baseline (issues found and reviewed before) to filter issues', metavar='baseline', default=r'')
    parser.add_argument('-l', help='Minimum level to show (1=informational, 2=warning, 3=critical)', metavar='level', default=1)

    parser.add_argument('--ignore-performance', action='store_true', default=False, help='Suppress performance-related rule issues')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    print(" ")
    print("                             ____    ___  ")
    print("     __  ______ __________ _/ __ \\  /   | ")
    print("    / / / / __ `/ ___/ __ `/ / / / / /| | ")
    print("   / /_/ / /_/ / /  / /_/ / /_/ / / ___ | ")
    print("   \\__, /\\__,_/_/   \\__,_/\\___\\_\\/_/  |_| ")
    print("  /____/                                  ")
    print(" ")
    print("   Florian Roth, January 2023, %s" % __version__)
    print(" ")
    # Logging
    logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
    Log = logging.getLogger(__name__)
    Log.setLevel(logging.INFO)
    # Console Handler
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    # Check the input files and directories
    input_files = []
    # File list
    if args.f:
        for f in args.f[0]:
            if not os.path.exists(f):
                Log.error("[E] Error: input file '%s' doesn't exist" % f)
            else:
                input_files.append(f)
    # Directory list
    elif args.d:
        for d in args.d[0]:
            if not os.path.exists(d):
                Log.error("[E] Error: input directory '%s' doesn't exist" % d)
            else:
                for dirpath, dirnames, files in os.walk(d):
                    for f in files:
                        if ".yar" in f:
                            input_files.append(os.path.join(dirpath, f))
    else:
            
        Log.error("[E] No input files selected")

    # Show selected input files
    if args.debug:
        Log.setLevel(level=logging.DEBUG)

    Log.debug("NUMBER OF INPUT FILES: %s" % len(input_files))

    # Create yaraQA object
    m = YaraQA(log=Log, debug=args.debug)

    # Read files
    Log.info("Reading input files ...")
    rule_sets = readFiles(input_files=input_files)
    Log.info("%d rule sets have been found and parsed" % len(rule_sets))

    # Analyze rules
    Log.info("Analyzing rules for issues ...")
    rule_issues = m.analyzeRules(rule_sets)
    Log.info("%d rule issues have been found (all types)" % len(rule_issues))

    # Print rule issues
    if len(rule_issues) > 0:
        # Output file preparation
        outfile = args.o
        # Now show the issues
        num_printed_issues = m.printIssues(rule_issues, outfile, int(args.l), args.b, args.ignore_performance)

        if num_printed_issues > 0:
            sys.exit(1)

    sys.exit(0)
