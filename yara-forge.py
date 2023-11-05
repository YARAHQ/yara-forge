#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# YARA Forge
# A YARA Rule Concentrator
# Florian Roth
# October 2023

import argparse
import pprint

from main.rules_collector import retrieve_yara_rule_sets
from main.rules_processors import process_yara_rules
from main.rule_output import write_yara_packages


if __name__ == "__main__":

   print(r'  __  _____    ____  ___       ______                     ');
   print(r'  \ \/ /   |  / __ \/   |     / ____/___  _________ ____  ');
   print(r'   \  / /| | / /_/ / /| |    / /_  / __ \/ ___/ __ `/ _ \ ');
   print(r'   / / ___ |/ _, _/ ___ |   / __/ / /_/ / /  / /_/ /  __/ ');
   print(r'  /_/_/  |_/_/ |_/_/  |_|  /_/    \____/_/   \__, /\___/  ');
   print(r'                                            /____/        ');
   print(r'  Florian Roth, October 2021                              ');

   parser = argparse.ArgumentParser()
   parser.add_argument("--debug", help="enable debug output", action="store_true")
   args = parser.parse_args()

   # Retrieve the YARA rule sets
   print("Retrieving YARA rules ...")
   yara_rule_repo_sets = retrieve_yara_rule_sets(args.debug)
   print("Found %d YARA rule sets" % len(yara_rule_repo_sets))
   #pprint.pprint(yara_rule_repo_sets)

   # Process the YARA rules
   print("Processing YARA rules ...")
   processed_yara_repos = process_yara_rules(yara_rule_repo_sets, args.debug)

   # Write the YARA packages
   print("Writing YARA packages ...")
   write_yara_packages(processed_yara_repos, args.debug)
