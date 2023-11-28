"""
This module contains functions for evaluating the quality of YARA rules.

It includes functions for checking syntax issues and efficiency issues in YARA rules,
and for reducing the quality score of a rule based on the issues found.
"""

import logging
import yaml
import yara
from plyara.utils import rebuild_yara_rule
from qa.yaraQA.main.core import YaraQA
#from pprint import pprint


def evaluate_rules_quality(processed_yara_repos, config):
    """
    Evaluates the quality of YARA rules.
    """

    # Create a yaraQA object
    yara_qa = YaraQA()

    # Create a copy of the the repos to work with
    processed_yara_repos_copy = processed_yara_repos.copy()

    # Loop over the repositories
    for repo_rule_sets in processed_yara_repos_copy:
        # Analyze the rule sets
        logging.info("Evaluating rules from repository: %s", repo_rule_sets['name'])
        # Issue statistics 
        issue_statistics = {
            "issues_syntax": 0,
            "issues_efficiency": 0
        }

        # Loop over the rule sets in the repository
        for rule_set in repo_rule_sets['rules_sets']:
            logging.debug("Evaluating rules from rule set: {rule_set['file_path']}")

            rules_without_errors = []

            # Now we do stuff with each rule
            for rule in rule_set['rules']:

                # Analyze the rule syntax
                # - Critical errors
                # - Compile issues
                issues_critical = check_issues_critical(rule)
                if issues_critical:
                    logging.warning("Rule %s has critical issues and cannot be used: %s", rule['rule_name'], issues_critical)
                    continue

                # Analyze the rule syntax
                # - Syntactical issues
                # - Compile issues
                issues_syntax = check_syntax_issues(rule)
                # Print the issues if debug is enabled
                logging.debug("Evaluated rule %s syntax issues: %s",
                              rule['rule_name'], issues_syntax)

                # Analyze the rule quality
                # Checks for
                # - Performance impact issues (based on experience)
                # - Resource usage issues (based on experience)
                # - Logic flaws (based on experience)
                issues_efficiency = yara_qa.analyze_rule(rule)
                # Print the issues if debug is enabled
                logging.debug("Evaluated rule %s efficiency issues: %s",
                              rule['rule_name'], issues_efficiency)

                # Analyze the rule performance
                # Checks for 
                # - Performance issues with live tests
                issues_performance = yara_qa.analyze_live_rule_performance(rule)

                # Reduce the rule's quality score based on the levels of 
                # the issues found in the rules
                issues = issues_syntax + issues_efficiency + issues_performance
                # Adding the values to the statistics
                issue_statistics['issues_syntax'] += len(issues_syntax)
                issue_statistics['issues_efficiency'] += len(issues_efficiency)
                # Loop over the issues
                for issue in issues:
                    issue['score'] = config['issue_levels'][issue['level']]
                # Calculate the total score
                total_score = sum(issue['score'] for issue in issues)

                # Apply a custom quality reduction if the rule has shown to be
                # prone to false positives
                custom_score_reduction = retrieve_custom_score_reduction(rule)
                total_score += custom_score_reduction

                # Debug output report the total score of a rule
                logging.debug("Rule %s total score: %d", rule['rule_name'], total_score)

                # Add the total score to the rule's quality score
                rule['metadata'] = modify_yara_rule_quality(rule['metadata'], total_score)

                # Add the rule to the list of rules without errors
                rules_without_errors.append(rule)

            # Replace the rules in the rule set with the rules without errors
            rule_set['rules'] = rules_without_errors

        # Print the issues statistics
        logging.info("Issues statistics: %d syntax issues, %d efficiency issues", 
                     issue_statistics['issues_syntax'], issue_statistics['issues_efficiency'])

    return processed_yara_repos_copy


def retrieve_custom_score_reduction(rule):
    """
    Retrieves a custom score reduction for a rule.
    """
    # Read the scores from the YAML file named custom-scoring.yml
    with open('custom-scoring.yml', 'r', encoding='utf-8') as f:
        custom_scoring = yaml.safe_load(f)
        # Loop over the rules in the YAML file
        for custom_score_reduction in custom_scoring['noisy-rules']:
            # Check if the rule name matches
            if custom_score_reduction['name'] == rule['rule_name']:
                # Return the score reduction
                return custom_score_reduction['quality']
    return 0

def check_syntax_issues(rule):
    """
    Checks for syntax issues in a YARA rule.
    """
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
        # Check for warnings
        yara.compile(source=yara_rule_string, error_on_warning=True)
    except Exception as e:
        issues.append({
                "rule": rule['rule_name'],
                "id": "SI2",
                "issue": "The rule didn't compile without issues",
                "element": {f"Error: {e}"},
                "level": 3,
                "type": "logic",
                "recommendation": "Check the warning message and fix the rule syntax",
            })
    return issues


def check_issues_critical(rule):
    """
    Checks for critical syntax issues in a YARA rule.
    """
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
        yara.compile(source=yara_rule_string)
    except Exception as e:
        issues.append({
                "rule": rule['rule_name'],
                "id": "SI1",
                "issue": "The rule didn't compile without errors",
                "element": {f"Error: {e}"},
                "level": 4,
                "type": "logic",
                "recommendation": "Fix the rule syntax and try again",
            })
    return issues


def modify_yara_rule_quality(rule_meta_data, reduction_value):
    """
    Modifies the quality score of a YARA rule.
    """
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


def check_yara_packages(repo_files):
    """
    Checks the YARA packages for errors.
    """
    # Loop over the list and print the file names
    for repo_file in repo_files:
        logging.info("Checking YARA package '%s' in file: %s", 
                     repo_file['name'], repo_file['file_path'])
        # Compile the rule set
        try:
            # Check for errors
            yara.compile(filepath=repo_file['file_path'])
        except Exception as e:
            logging.error("The rule set didn't compile without errors: %s", e)
            return False
    return True


def get_yara_qa_commit_hash():
    """
    Returns the current commit hash of the lst commit of the YARA QA sub repository.
    """
    # Get the current commit hash of the YARA QA sub repository
    try:
        with open(".git/modules/qa/yaraQA/refs/heads/main", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logging.warning("Couldn't get the commit hash of the YARA QA repository: %s", e)
        return "unknown"
