#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# YARA Forge
# A YARA Rule Concentrator
# Florian Roth
# July 2025

__version__ = '0.9.1'

import argparse
#import pprint
import logging
import sys
import yaml

from main.rule_collector import retrieve_yara_rule_sets
from main.rule_processors import process_yara_rules
from main.rule_output import write_yara_packages
from qa.rule_qa import evaluate_rules_quality, check_yara_packages, get_yara_qa_commit_hash



# Write a section header with dividers
def write_section_header(title, divider_with=72):
    print("\n" + "=" * divider_with)
    print(title.center(divider_with).upper())
    print("=" * divider_with + "\n")


if __name__ == "__main__":

    print(r'  __  _____    ____  ___       ______                     ')
    print(r'  \ \/ /   |  / __ \/   |     / ____/___  _________ ____  ')
    print(r'   \  / /| | / /_/ / /| |    / /_  / __ \/ ___/ __ `/ _ \ ')
    print(r'   / / ___ |/ _, _/ ___ |   / __/ / /_/ / /  / /_/ /  __/ ')
    print(r'  /_/_/  |_/_/ |_/_/  |_|  /_/    \____/_/   \__, /\___/  ')
    print(r'                                            /____/        ')
    print(r'  YARA Forge                                              ')
    print(r'  Bringing Order to Chaos                                 ')
    print(r'                                                          ')
    print(r'  Version %s                                              ' % __version__)
    print(r'  Florian Roth, July 2025                                 ')

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="enable debug output", action="store_true")
    parser.add_argument("-c", "--config", help="specify a different config file", default="yara-forge-config.yml")
    args = parser.parse_args()

    # Create a new logger to log into the command line and a log file name yara-forge.log
    # (only set the level to debug if the debug argument is set)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Set the level of the plyara logger to warning
    logging.getLogger('plyara').setLevel(logging.WARNING)
    logging.getLogger('tzlocal').setLevel(logging.CRITICAL)
    # Create a handler for the command line
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Create a handler for the log file
    fh = logging.FileHandler("yara-forge.log")
    fh.setLevel(logging.DEBUG)
    # Create a formatter for the log messages that go to the log file
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Create a formatter for the log messages that go to the command line
    formatter_cmd = logging.Formatter('%(message)s')
    # Add the formatter to the handlers
    ch.setFormatter(formatter_cmd)
    fh.setFormatter(formatter)
    # Add the handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    # Read configuration file
    with open(args.config, 'r') as f:
        YARA_FORGE_CONFIG = yaml.safe_load(f)

    # Retrieve the YARA rule sets
    write_section_header("Retrieving YARA rule sets")
    yara_rule_repo_sets = retrieve_yara_rule_sets(
        YARA_FORGE_CONFIG['repo_staging_dir'], 
        YARA_FORGE_CONFIG['yara_repositories'])
    #pprint.pprint(yara_rule_repo_sets)

    # Process the YARA rules
    write_section_header("Processing YARA rules")
    processed_yara_repos = process_yara_rules(yara_rule_repo_sets, YARA_FORGE_CONFIG)

    # Evaluate the quality of the rules
    write_section_header("Evaluating YARA rules")
    evaluated_yara_repos = evaluate_rules_quality(processed_yara_repos, YARA_FORGE_CONFIG)

    # Write the YARA packages
    write_section_header("Writing YARA packages")
    repo_files = write_yara_packages(evaluated_yara_repos, program_version=__version__, yaraqa_commit=get_yara_qa_commit_hash(), YARA_FORGE_CONFIG=YARA_FORGE_CONFIG)

    # We quality check the output files and look for errors
    write_section_header("Quality checking YARA packages")
    test_successful = check_yara_packages(repo_files)
    if test_successful:
        logging.log(logging.INFO, "Quality check finished successfully")
        sys.exit(0)
    else:
        logging.log(logging.ERROR, "Quality check failed")
        sys.exit(1)
