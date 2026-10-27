"""
This module contains functions for evaluating the quality of YARA rules.

It includes functions for checking syntax issues and efficiency issues in YARA rules,
and for reducing the quality score of a rule based on the issues found.
"""

import logging
import datetime
import yaml
import yara
from plyara.utils import rebuild_yara_rule
from qa.yaraQA.main.core import YaraQA
from pprint import pprint


def evaluate_rules_quality(processed_yara_repos, config):
    """
    Evaluates the quality of YARA rules.
    """

    # Create a yaraQA object
    yara_qa = YaraQA()

    # Rule issues list
    repo_issues = {}

    # Create a copy of the the repos to work with
    processed_yara_repos_copy = processed_yara_repos.copy()

    # Loop over the repositories
    for repo_rule_sets in processed_yara_repos_copy:
        # Analyze the rule sets
        logging.info("Evaluating rules from repository: %s", repo_rule_sets['name'])
        # Issue statistics 
        issue_statistics = {
            "issues_syntax": 0,
            "issues_efficiency": 0,
            "issues_performance": 0,
            "issues_critical": 0,
        }

        # Loop over the rule sets in the repository
        for rule_set in repo_rule_sets['rules_sets']:
            logging.debug("Evaluating rules from rule set: {rule_set['file_path']}")

            rules_without_errors = []

            # Now we do stuff with each rule
            for rule in rule_set['rules']:

                # Skip the rule if it has critical issues
                skip_rule = False

                # Analyze the rule syntax
                # - Critical errors
                # - Compile issues
                issues_critical = check_issues_critical(rule)
                # Rule has critical issues
                if issues_critical:
                    # Adding the values to the statistics
                    issue_statistics['issues_critical'] += len(issues_critical)
                    logging.warning("Rule %s has critical issues and cannot be used: %s", rule['rule_name'], issues_critical)
                    skip_rule = True

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
                # Add the values to the statistics
                issue_statistics['issues_performance'] += len(issues_performance)

                # Reduce the rule's quality score based on the levels of 
                # the issues found in the rules
                issues = issues_syntax + issues_efficiency + issues_performance + issues_critical
                # Adding the values to the statistics
                issue_statistics['issues_syntax'] += len(issues_syntax)
                issue_statistics['issues_efficiency'] += len(issues_efficiency)
                # Loop over the issues
                for issue in issues:
                    issue['score'] = config['issue_levels'][issue['level']]
                # Calculate the total score
                total_quality_score = sum(issue['score'] for issue in issues)

                # Reduce score to 40 if it uses the yara elf module, because that slows down the whole scanning
                # (will probably change with yara-x)
                # This way, rules which use the "elf" module only appear in the full package
                if 'imports' in rule and 'elf' in rule['imports']:
                    modify_meta_data_value(rule['metadata'], 'score', 40)

                # Apply a custom quality reduction if the rule has shown to be
                # prone to false positives
                custom_quality_reduction = retrieve_custom_quality_reduction(rule)
                total_quality_score += custom_quality_reduction

                # Apply a custom score if the rule has shown to be
                # prone to false positives
                custom_score = retrieve_custom_score(rule)
                if custom_score:
                    modify_meta_data_value(rule['metadata'], 'score', custom_score)

                # Debug output report the total score of a rule
                logging.debug("Rule %s total quality score: %d", rule['rule_name'], total_quality_score)

                # Add the total score to the rule's quality score
                rule['metadata'] = modify_yara_rule_quality(rule['metadata'], total_quality_score)

                # Add all issues to the big list of issues
                if repo_rule_sets['name'] in repo_issues:
                    repo_issues[repo_rule_sets['name']].extend(issues)
                else:
                    repo_issues[repo_rule_sets['name']] = issues

                # Add the rule to the list of rules without errors
                if not skip_rule:
                    rules_without_errors.append(rule)

            # Replace the rules in the rule set with the rules without errors
            rule_set['rules'] = rules_without_errors

        # Print the issues statistics
        logging.info("Issues statistics: %d syntax issues, %d efficiency issues, " +
                     "%d performance issues, %d critical issues",
                     issue_statistics['issues_syntax'],
                     issue_statistics['issues_efficiency'],
                     issue_statistics['issues_performance'],
                     issue_statistics['issues_critical'])

    # Log the issues found in the rules to a separate file
    write_issues_to_file(repo_issues)

    # Return the processed repos
    return processed_yara_repos_copy


def write_issues_to_file(rule_issues):
    """
    Writes the issues found in the rules to a separate file.
    """
    # Write the issues to a file
    with open("yara-forge-rule-issues.yml", "w", encoding="utf-8") as f:
        # Write a comment on top of the YAML file that explains what the file contains
        f.write("# This file contains the issues found in the YARA rules during the QA checks\n")
        f.write("# The issues are grouped by repository\n")
        f.write("# Important: remember that the issues have different severity levels (1-4)\n")
        f.write("# - 1: only cosmetic or minor issues\n")
        f.write("# - 2: issues that have a minor impact on performance / resource usage\n")
        f.write("# - 3: issues that have a major impact on performance / resource usage and show a lack of care\n")
        f.write("# - 4: issues that are critical; mostly it's a broken rule or rules that use external variables (not available in every tool)\n")
        # Write a timestamp and some statistics
        f.write(f"# Timestamp: {datetime.datetime.now()}\n")
        f.write(f"# Total number of issues: {sum(len(v) for v in rule_issues.values())}\n")
        f.write(f"# Total number of repositories: {len(rule_issues)}\n")
        # Write the issues to the file
        yaml.dump(rule_issues, f, sort_keys=False, allow_unicode=True)


def retrieve_custom_quality_reduction(rule):
    """
    Retrieves a custom quality score reduction for a rule.
    """
    # Read the scores from the YAML file named yara-forge-custom-scoring.yml
    with open('yara-forge-custom-scoring.yml', 'r', encoding='utf-8') as f:
        custom_scoring = yaml.safe_load(f)
        # Loop over the rules in the YAML file
        for custom_score in custom_scoring['noisy-rules']:
            # Check if the rule name matches
            if custom_score['name'] == rule['rule_name']:
                if 'quality' in custom_score:
                    # Return the score reduction
                    return custom_score['quality']
            # Check if the rule name starts with the name in the YAML file
            if 'type' in custom_score:
                if custom_score['type'] == 'prefix':
                    if rule['rule_name'].startswith(custom_score['name']):
                        if 'quality' in custom_score:
                            # Return the score reduction
                            return custom_score['quality']
    return 0


def retrieve_custom_score(rule):
    """
    Retrieves a custom score for a rule.
    """
    # Read the scores from the YAML file named yara-forge-custom-scoring.yml
    with open('yara-forge-custom-scoring.yml', 'r', encoding='utf-8') as f:
        custom_scoring = yaml.safe_load(f)
        # Loop over the rules in the YAML file
        for custom_score in custom_scoring['noisy-rules']:
            # Check if the rule name matches
            if custom_score['name'] == rule['rule_name']:
                if 'score' in custom_score:
                    # Return the score reduction
                    return custom_score['score']
            # Check if the rule name starts with the name in the YAML file
            if 'type' in custom_score:
                if custom_score['type'] == 'prefix':
                    if rule['rule_name'].startswith(custom_score['name']):
                        if 'score' in custom_score:
                            # Return the score reduction
                            return custom_score['score']
    return None




def check_syntax_issues(rule):
    """
    Checks for syntax issues in a YARA rule.
    """
    # Syntax issues list
    issues = []

    # Check if the rule requires some private rules
    prepended_private_rules_string = ""
    if 'private_rules_used' in rule:
        with open('yara-forge-custom-scoring.yml', 'r', encoding='utf-8') as f:
            custom_scoring = yaml.safe_load(f)
            for priv_rule in rule['private_rules_used']:
                # Check if the name of this private rule appears in noisy-rules and don't include the rule then.
                # This means, that the 3 ESET rules, which use a private rule with elf module won't even make it in the full package
                # but I don't see an easy fix and the effort isn't worth it for 3 rules I suppose.
                if not any(d['name'] == priv_rule['new_name'] for d in custom_scoring['noisy-rules']):
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
        logging.debug("Rule %s has critical issues and cannot be used: %s", rule['rule_name'], yara_rule_string)
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


def modify_meta_data_value(rule_meta_data, key, value):
    """
    Modify a value in the meta data, if it exists, otherwise add it
    """
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for mdata in meta_data_copy:
        for k, _ in mdata.items():
            # If the key is in the meta data, then we modify it
            if k == key:
                mdata[k] = value
                return mdata
    # If the key is not in the meta data, then we add it
    rule_meta_data.append({key: value})
    return rule_meta_data

