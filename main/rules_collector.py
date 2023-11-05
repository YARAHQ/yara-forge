import os
import requests
import shutil
import tempfile
import plyara
import datetime
import logging

YARA_REPOS = [
   {
      "name": "YARA Style Guide",  # used in headers and as prefix for each of the rules (so keep it short)
      "url": 'https://github.com/Neo23x0/YARA-Style-Guide',  # URL of the repository on GitHub
      "author": "Florian Roth",  # used when the author is not defined in the rule
      "owner": 'Neo23x0',  # name of the owner of the repository on GitHub
      "repo": "YARA-Style-Guide",  # name of the repository on GitHub
      "quality": 70,  # 0-100 (0 = low, 100 = high) base value; indicates the quality of the rules in the repository
      "branch": "master"  # name of the branch to download
   },
]

# Retrieve YARA rules from online repositories
def retrieve_yara_rule_sets(logger):
   
   yara_rule_repo_sets = []
   
   # Loop over the repositories
   for repo in YARA_REPOS:
      
      # Output the repository information to the console in a single line
      logger.log(logging.INFO, "Retrieving YARA rules from repository: %s" % repo['name'])

      # Download the latest version of the repository
      response = requests.get(f"{repo['url']}/archive/refs/heads/{repo['branch']}.zip")
      with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
         tmp_file.write(response.content)
         tmp_file.flush()

         # Extract the downloaded zip file
         with tempfile.TemporaryDirectory() as tmp_dir:
            shutil.unpack_archive(tmp_file.name, tmp_dir, format="zip")

            # Walk through the extracted folders and find a LICENSE file and save it into the repository object
            for root, dirs, files in os.walk(tmp_dir):
               for file in files:
                  if file == "LICENSE" or file == "LICENSE.txt" or file == "LICENSE.md":
                     file_path = os.path.join(root, file)
                     with open(file_path, "r") as f:
                        repo['license'] = f.read()
                        break

            # Walk through the extracted folders and find all YARA files
            yara_rule_sets = []
            for root, dirs, files in os.walk(tmp_dir):
               for file in files:
                  if file.endswith(".yar") or file.endswith(".yara"):
                     file_path = os.path.join(root, file)

                     # Debug output
                     logger.log(logging.DEBUG, "Found YARA rule file: %s" % file_path)

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
                           logger.log(logging.DEBUG, "Found %d YARA rules in file: %s" % (len(yara_rules), file_path))
                           # Append to list of YARA rule sets
                           yara_rule_sets.append(yara_rule_set)
                           
                        except Exception as e:
                           print(e)
                           logger.log(logging.ERROR, "Skipping YARA rule in the following file because of a syntax error: %s " % file_path)
            
         # Append the YARA rule repository
         yara_rule_repo = {
            "name": repo['name'],
            "url": repo['url'],
            "author": repo['author'],
            "owner": repo['owner'],
            "repo": repo['repo'],
            "branch": repo['branch'],
            "rules_sets": yara_rule_sets,
            "quality": repo['quality'],
            "license": repo['license'],
            "retrieval_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         }
         yara_rule_repo_sets.append(yara_rule_repo)

         logger.log(logging.INFO, "Retrieved %d YARA rules from repository: %s" % (len(yara_rule_sets), repo['name']))

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
