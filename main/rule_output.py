import pprint
import os
import dateparser
import datetime
from pprint import pprint
from plyara.utils import rebuild_yara_rule
import logging

# YARA rule packages
YARA_RULE_PACKAGES = [
   {
      "name": "default",
      "description": "Default YARA rule package",
      "minimum_quality": 50, # based on the quality score
      "minimum_age": 7, # in days
   }
]

REPO_HEADER = """
/* ----------------------------------------------------------------------------------------------
 * YARA rules
 * Repository: {repo_url}
 * Retrieval date: {retrieval_date}
 * ---------------------------------------------------------------------------------------------- 

 LICENSE

 {repo_license}

 */
"""

# Loop over the rules and write them as plain text into separate files
def write_yara_packages(processed_yara_repos, logger):
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
            # Debug output
            logging.log(logging.DEBUG, "Writing YARA rules from repository: %s" % repo['name'])
            # Write header into the output file for each repository
            f.write(REPO_HEADER.format(repo_url=repo['url'], retrieval_date=repo['retrieval_date'], repo_license=repo['license']))
            # Loop over the rule sets in the repository and modify the rules
            for rule_sets in repo['rules_sets']:
               # Debug output
               logging.log(logging.DEBUG, "Writing YARA rules from rule set: %s" % rule_sets['file_path'])
               # Loop over the rules in the rule set
               for rule in rule_sets['rules']:

                  # Perform some check based on the meta data of the rule
                  skip_rule = False
                  # Loop over the metadata
                  for metadata in rule['metadata']:

                     # Check if the rule has a minimum age
                     if "date" in metadata:
                        rule_date = dateparser.parse(metadata['date'])
                        # Check if the rule is old enough
                        if (datetime.datetime.now() - rule_date).days < rule_package['minimum_age']:
                           logger.log(logging.DEBUG, "Skipping rule %s because it is too young: %s" % (rule['rule_name'], metadata['date']))
                           skip_rule = True

                     if "quality" in metadata:
                        # Check if the rule has the require quality
                        if metadata['quality'] < rule_package['minimum_quality']:
                           logger.log(logging.DEBUG, "Skipping rule %s because of insufficient quality score: %d" % (rule['rule_name'], metadata['quality']))
                           skip_rule = True

                  if skip_rule:
                     continue

                  # Write the rule into the output file
                  f.write(rebuild_yara_rule(rule))
