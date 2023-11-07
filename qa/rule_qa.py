import logging
from pprint import pprint
from qa.yaraQA.main.core import YaraQA

def evaluate_rules_quality(processed_yara_repos, logger=None):
   # Create a yaraQA object
   yaraQA = YaraQA(log=logger)
   for repo_rule_sets in processed_yara_repos:
      # Analyze the rule sets
      logger.log(logging.INFO, "Analyzing rules from repository: %s" % repo_rule_sets['name'])
      for rule_set in repo_rule_sets['rules_sets']:
         logger.log(logging.INFO, "Analyzing rules from rule set: %s" % rule_set['file_path'])
         for rule in rule_set['rules']:
            # Analyze the rule
            issues = yaraQA.analyze_rule(rule)
            # Print the issues if debug is enabled
            if logger.isEnabledFor(logging.DEBUG):
               print(issues)
