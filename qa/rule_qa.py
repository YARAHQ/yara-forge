import logging
import yara
from plyara.utils import rebuild_yara_rule
from pprint import pprint
from qa.yaraQA.main.core import YaraQA

# Explanations for the different issue levels used in the rule quality analysis
# Level 1 - cosmetic issues with the rule
# Level 2 - minor issues with the rule
# Level 3 - major issues with the rule
# Level 4 - critical issues with the rule

# Levels and quality score reduction
ISSUE_LEVELS = {
   1: 5,
   2: 20,
   3: 40,
   4: 100
}

def evaluate_rules_quality(processed_yara_repos):

   # Create a yaraQA object
   yaraQA = YaraQA()

   # Loop over the repositories
   for repo_rule_sets in processed_yara_repos:
      # Analyze the rule sets
      logging.log(logging.INFO, "Evaluating rules from repository: %s" % repo_rule_sets['name'])
      # Issue statistics 
      issue_statistics = {
         "issues_syntax": 0,
         "issues_efficiency": 0
      }

      # Loop over the rule sets in the repository
      for rule_set in repo_rule_sets['rules_sets']:
         logging.log(logging.DEBUG, "Evaluating rules from rule set: %s" % rule_set['file_path'])
         
         # Now we do stuff with each rule
         for rule in rule_set['rules']:

            # Analyze the rule syntax
            # - Syntactical issues
            # - Compile issues
            issues_syntax = check_syntax_issues(rule)
            # Print the issues if debug is enabled
            logging.log(logging.DEBUG, f"Evaluated rule {rule['rule_name']} syntax issues: {issues_syntax}")

            # Analyze the rule quality 
            # Checks for
            # - Performance impact issues
            # - Resource usage issues
            issues_efficiency = yaraQA.analyze_rule(rule)
            # Print the issues if debug is enabled
            logging.log(logging.DEBUG, f"Evaluated rule {rule['rule_name']} efficiency issues: {issues_efficiency}")

            # Reduce the rule's quality score based on the levels of the issues found in the rules
            issues = issues_syntax + issues_efficiency
            # Adding the values to the statistics
            issue_statistics['issues_syntax'] += len(issues_syntax)
            issue_statistics['issues_efficiency'] += len(issues_efficiency)
            # Loop over the issues
            for issue in issues:
               issue['score'] = ISSUE_LEVELS[issue['level']]
            # Calculate the total score   
            total_score = sum([issue['score'] for issue in issues])
            # Add the total score to the rule's quality score 
            rule['metadata'] = modify_yara_rule_quality(rule['metadata'], -total_score)

      # Print the issues statistics
      logging.log(logging.INFO, f"Issues statistics: {issue_statistics['issues_syntax']} syntax issues, {issue_statistics['issues_efficiency']} efficiency issues")


def check_syntax_issues(rule):
   # Syntax issues list
   issues = []

   # Check if the rule requires some private rules
   prepended_private_rules_string = ""
   if 'private_rules_used' in rule:
      for priv_rule in rule['private_rules_used']:
         # Get the rule from the plyara object
         priv_rule_string = rebuild_yara_rule(priv_rule["rule"])
         # Add the rule to the string
         prepended_private_rules_string += priv_rule_string + "\n"

   # Get the serialized rule from the plyara object
   yara_rule_string = prepended_private_rules_string + rebuild_yara_rule(rule)

   # Compile the rule
   try:
      # Check for errors
      compiled_rule = yara.compile(source=yara_rule_string)
   except Exception as e:
      issues.append({
            "rule": rule['rule_name'],
            "id": "SI1",
            "issue": "The rule didn't compile without errors",
            "element": {"Error: %s" % e},
            "level": 4,
            "type": "logic",
            "recommendation": "Fix the rule syntax and try again",
         })
   try:
      # Check for warnings
      compiled_rule = yara.compile(source=yara_rule_string, error_on_warning=True)
   except Exception as e:
      issues.append({
            "rule": rule['rule_name'],
            "id": "SI2",
            "issue": "The rule didn't compile without issues",
            "element": {"Error: %s" % e},
            "level": 3,
            "type": "logic",
            "recommendation": "Check the warning message and fix the rule syntax",
         })
   return issues

# Modify the quality score of a YARA rule
def modify_yara_rule_quality(rule_meta_data, reduction_value):
   # We create a copy so that we can delete elements from the original
   meta_data_copy = rule_meta_data.copy()
   # Now we loop over the copy
   for mdata in meta_data_copy:
      for k, v in mdata.items():
         # If the key is in the meta data, then we modify it
         if k == "quality":
            mdata[k] += reduction_value
            return meta_data_copy
   return rule_meta_data
