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
import shutil
import tempfile
import requests
import plyara

YARA_REPOS = [
   'https://github.com/embee-research/Yara-detection-rules'
]

def retrieve_yara_rule_sets(urls):
   yara_files = []
   for url in YARA_REPOS:
      # Download the latest version of the repository
      response = requests.get(f"{url}/archive/refs/heads/main.zip")
      with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
         tmp_file.write(response.content)
         tmp_file.flush()

         # Extract the downloaded zip file
         with tempfile.TemporaryDirectory() as tmp_dir:
            shutil.unpack_archive(tmp_file.name, tmp_dir)

            # Walk through the extracted folders and find all YARA files
            for root, dirs, files in os.walk(tmp_dir):
               for file in files:
                  if file.endswith(".yar") or file.endswith(".yara"):
                     file_path = os.path.join(root, file)
                     with open(file_path, "r") as f:
                        yara_file = f.read()
                        parsed_yara = plyara.parse_string(yara_file)
                        yara_files.append(parsed_yara)
                        if args.debug:
                           print(f"Added YARA file {file_path} to yara_files list")

   return yara_files

def parse_yara_files(rule_sets):
   yara_files = []
   for rule_set in rule_sets:
      for root, dirs, files in os.walk(rule_set):
         for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
               file_path = os.path.join(root, file)
               with open(file_path, "r") as f:
                  yara_file = f.read()
                  parsed_yara = plyara.parse_string(yara_file)
                  yara_files.append(parsed_yara)
   return yara_files

def process_yara_rules(yara_files):
   # TODO: Implement function to modify YARA rules
   pass

def write_yara_packages(yara_files):
   # TODO: Implement function to write YARA packages
   pass

if __name__ == "__main__":

   parser = argparse.ArgumentParser()
   parser.add_argument("--debug", help="enable debug output", action="store_true")
   args = parser.parse_args()

   rule_sets = retrieve_yara_rule_sets()
   yara_files = parse_yara_files(rule_sets)
   processed_yara_files = process_yara_rules(yara_files)
   write_yara_packages(processed_yara_files)
