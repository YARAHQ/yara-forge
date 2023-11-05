import pprint
import os
from plyara.utils import rebuild_yara_rule

# YARA rule packages
YARA_RULE_PACKAGES = [
   {
      "name": "default",
      "description": "Default YARA rule package",
      "minimum_quality": "medium", # low, medium, high
      "maximum_performance_impact": "medium" # low, medium, high
   }
]

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
