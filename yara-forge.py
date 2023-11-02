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
import plyara

from main.rules_collector import retrieve_yara_rule_sets

def process_yara_rules(yara_files):
   # TODO: Implement function to modify YARA rules
   pass

def write_yara_packages(yara_files):
   # TODO: Implement function to write YARA packages
   pass

if __name__ == "__main__":

   print(r'  __  _____    ____  ___       ______                     ');
   print(r'  \ \/ /   |  / __ \/   |     / ____/___  _________ ____  ');
   print(r'   \  / /| | / /_/ / /| |    / /_  / __ \/ ___/ __ `/ _ \ ');
   print(r'   / / ___ |/ _, _/ ___ |   / __/ / /_/ / /  / /_/ /  __/ ');
   print(r'  /_/_/  |_/_/ |_/_/  |_|  /_/    \____/_/   \__, /\___/  ');
   print(r'                                            /____/        ');

   parser = argparse.ArgumentParser()
   parser.add_argument("--debug", help="enable debug output", action="store_true")
   args = parser.parse_args()

   yara_rule_sets = retrieve_yara_rule_sets()

   processed_yara_files = process_yara_rules(yara_rule_sets)
   write_yara_packages(processed_yara_files)
