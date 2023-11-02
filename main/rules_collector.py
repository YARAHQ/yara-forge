import os
import requests
import shutil
import tempfile
import plyara

YARA_REPOS = [
   {
      "name": "Embee Research",
      "url": 'https://github.com/embee-research/Yara-detection-rules',
      "quality": "high"
   },
]

# Retrieve YARA rules from online repositories
def retrieve_yara_rule_sets():
   
   yara_rule_sets = []
   
   # Loop over the repositories
   for repo in YARA_REPOS:
      # Download the latest version of the repository
      response = requests.get(f"{repo['url']}/archive/refs/heads/main.zip")
      with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
         tmp_file.write(response.content)
         tmp_file.flush()

         # Extract the downloaded zip file
         with tempfile.TemporaryDirectory() as tmp_dir:
            shutil.unpack_archive(tmp_file.name, tmp_dir, format="zip")

            # Walk through the extracted folders and find all YARA files
            yara_rules_string = ""
            for root, dirs, files in os.walk(tmp_dir):
               for file in files:
                  if file.endswith(".yar") or file.endswith(".yara"):
                     file_path = os.path.join(root, file)
                     with open(file_path, "r") as f:
                        yara_file_content = f.read()
                        yara_rules_string += yara_file_content
            
            # Parse the YARA rules
            parsed_yara_rules = plyara.Parser(yara_rules_string)

            # New YARA rule set
            yara_rule_set = {
               "name": repo['name'],
               "url": repo['url'],
               "rules": parsed_yara_rules
            }

            # Append to list of YARA rule sets
            yara_rule_sets.append(yara_rule_set)

   # Return the YARA rule sets
   return yara_rule_sets
