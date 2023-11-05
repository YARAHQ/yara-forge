import os
import sys
import requests
import shutil
import tempfile
import plyara
import datetime

YARA_REPOS = [
   {
      "name": "YARA Style Guide",
      "url": 'https://github.com/Neo23x0/YARA-Style-Guide',
      "author": "Florian Roth",
      "owner": 'Neo23x0',
      "repo": "YARA-Style-Guide",
      "quality": "high",
      "branch": "master"
   },
]

# Retrieve YARA rules from online repositories
def retrieve_yara_rule_sets(debug=False):
   
   yara_rule_repo_sets = []
   
   # Loop over the repositories
   for repo in YARA_REPOS:
      # Download the latest version of the repository
      response = requests.get(f"{repo['url']}/archive/refs/heads/{repo['branch']}.zip")
      with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
         tmp_file.write(response.content)
         tmp_file.flush()

         # Extract the downloaded zip file
         with tempfile.TemporaryDirectory() as tmp_dir:
            shutil.unpack_archive(tmp_file.name, tmp_dir, format="zip")

            # Walk through the extracted folders and find all YARA files
            yara_rule_sets = []
            for root, dirs, files in os.walk(tmp_dir):
               for file in files:
                  if file.endswith(".yar") or file.endswith(".yara"):
                     file_path = os.path.join(root, file)

                     # Debug output
                     if debug:
                        print("Parsing YARA file: %s" % file_path)

                     # Read the YARA file
                     with open(file_path, "r") as f:
                        yara_file_content = f.read()
                        # Parse the rules in the file
                        try:
                           # Get the rule file path in the repository
                           relative_path = os.path.relpath(file_path, start=tmp_dir)
                           relative_path_without_first_segment = os.path.join(*relative_path.split(os.path.sep)[1:])
                           # Parse the YARA rules in the file
                           yara_parser = plyara.Plyara()
                           yara_rules = yara_parser.parse_string(yara_file_content)
                           # Create a YARA rule set object
                           yara_rule_set = {
                              "rules": yara_rules,
                              "file_path": relative_path_without_first_segment,
                           }
                           # Debug output
                           if debug:
                              print("Found %d YARA rules in file: %s" % (len(yara_rules), file_path))
                           # Append to list of YARA rule sets
                           yara_rule_sets.append(yara_rule_set)
                           
                        except Exception as e:
                           print(e)
                           print("Skipping YARA rule in the following file because of a syntax error: %s " % file_path)
            
         # Append the YARA rule repository
         yara_rule_repo = {
            "name": repo['name'],
            "url": repo['url'],
            "owner": repo['owner'],
            "repo": repo['repo'],
            "branch": repo['branch'],
            "rules_sets": yara_rule_sets,
            "quality": repo['quality'],
            "retrieval_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         }
         yara_rule_repo_sets.append(yara_rule_repo)

   # Return the YARA rule sets
   return yara_rule_repo_sets


def check_yara_rule(yara_rule_string):
   yara_parser = plyara.Plyara()
   try:
      yara_parser.parse_string(yara_rule_string) 
      return True
   except Exception as e:
      print(e)
      return False
