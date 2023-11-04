#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# YARA Forge
# A YARA Rule Concentrator
# Florian Roth
# October 2023

import os
import argparse
import pprint
from plyara.utils import rebuild_yara_rule

from main.rules_collector import retrieve_yara_rule_sets
from main.rules_processors import *

# YARA rule packages
YARA_RULE_PACKAGES = [
   {
      "name": "default",
      "description": "Default YARA rule package",
      "minimum_quality": "medium", # low, medium, high
      "maximum_performance_impact": "medium" # low, medium, high
   }
]

# Process the YARA rules
def process_yara_rules(yara_rule_repo_sets, debug=False):
   # Loop over the repositories
   for repo in yara_rule_repo_sets:
      # Rule set identifier
      rule_set_id = repo['name'].replace(" ", "_").upper()
      # Debug output
      if debug:
         print("Processing YARA rules from repository: %s" % repo['name'])
      # Loop over the rule sets in the repository and modify the rules
      for rules in repo['rules_sets']:
         # Debug output
         if debug:
            print("Processing YARA rules from rule set: %s" % rules['file_path'])
         # Loop over each of the rules and modify them
         for rule in rules['rules']:
            # Debug output
            if debug:
               print("Processing YARA rule: %s" % rule['rule_name'])
            # Modify the rule name
            rule['rule_name'] = process_yara_rule_name(rule['rule_name'], rule_set_id)
            # Modify the rule references
            rule['metadata'] = process_yara_rule_reference(rule['metadata'], repo['url'])
            # # Modify the rule date
            # rule['metadata'] = process_yara_rule_date(rule['metadata'], repo['url'], rules['file_path'])
            # # Modify the rule tags
            # rule['metadata'] = process_yara_rule_tags(rule['metadata'], repo['tags'])
            # # Modify the rule description
            # rule['metadata'] = process_yara_rule_description(rule['metadata'], repo['description'])
            # # Modify the rule author
            # rule['metadata'] = process_yara_rule_author(rule['metadata'], repo['author'])
            # # Modify the rule license
            # rule['metadata'] = process_yara_rule_license(rule['metadata'], repo['license'])
            # # Modify the rule version
            # rule['metadata'] = process_yara_rule_version(rule['metadata'], repo['version'])
            # # Modify the rule strings
            # rule['strings'] = process_yara_rule_strings(rule['strings'])
            # # Modify the rule condition
            # rule['condition'] = process_yara_rule_condition(rule['condition'])
             
   # Debug output
   #pprint.pprint(yara_rule_repo_sets)
   return yara_rule_repo_sets

# Loop over the rules and write them as plain text into separate files
def write_yara_packages(processed_yara_repos, debug=False):
   for rule_package in YARA_RULE_PACKAGES:
      # Create the directory for the rule package
      package_dir = os.path.join("packages", rule_package['name'])
      if not os.path.exists(package_dir):
         os.makedirs(package_dir)
      # Create the rule file name
      rule_file_name = "yara-rules-%s.yar" % rule_package['name']
      # Create the rule file path
      rule_file_path = os.path.join(package_dir, rule_file_name)
      # Write the rule file
      with open(rule_file_path, "w") as f:
         # Loop over the repositories
         for repo in processed_yara_repos:
            pprint.pprint(repo)
            # Rule set identifier
            rule_set_id = repo['name'].replace(" ", "_").upper()
            # Debug output
            if debug:
               print("Writing YARA rules from repository: %s" % repo['name'])
            # Loop over the rule sets in the repository and modify the rules
            for rule_sets in repo['rules_sets']:
               # Debug output
               if debug:
                  print("Writing YARA rules from rule set: %s" % rule_sets['file_path'])
               for rule in rule_sets['rules']:
                  f.write(rebuild_yara_rule(rule))


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
