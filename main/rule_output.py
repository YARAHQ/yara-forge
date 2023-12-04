"""
This module contains functions for writing YARA rules into separate files.
"""
import os
import logging
import datetime
from pprint import pprint
import dateparser
from plyara.utils import rebuild_yara_rule


def write_yara_packages(processed_yara_repos, program_version, yaraqa_commit, YARA_FORGE_CONFIG):
    """
    Writes YARA rules into separate files.
    """

    # List of files that were written
    package_files = []

    rule_package_statistics_set = []

    # Loop over the rule packages
    for rule_package in YARA_FORGE_CONFIG['yara_rule_packages']:

        # Statistics for the rule package
        rule_package_statistics = {
            "total_rules": 0,
            "total_rules_skipped_age": 0,
            "total_rules_skipped_quality": 0,
            "total_rules_skipped_importance": 0,
            "total_rules_skipped_score": 0,
            "repo_statistics": [],
            "name": rule_package['name'],
        }

        # Create the directory for the rule package
        package_dir = os.path.join("packages", rule_package['name'])
        if not os.path.exists(package_dir):
            os.makedirs(package_dir)
        # Create the rule file name
        rule_file_name = f"yara-rules-{rule_package['name']}.yar"
        # Create the rule file path
        rule_file_path = os.path.join(package_dir, rule_file_name)

        # Write information about the rule package, the output file name
        # and the output file path to the console
        logging.info("------------------------------------------------------------------------")
        logging.info("Creating YARA rule package '%s': %s", rule_package['name'], rule_file_path)
        logging.info("Description: %s", rule_package['description'])
        logging.info("Minimum Quality: %d", rule_package['minimum_quality'])
        logging.info("Minimum Age: %d", rule_package['minimum_age'])
        logging.info("Output File: %s", rule_file_path)

        # List of strings composed of the rules from each repository
        output_rule_set_strings = []

        # Loop over the repositories
        for repo in processed_yara_repos:
            # Debug output
            logging.info("Writing YARA rules from repository: %s", repo['name'])

            # Repo rule set string
            repo_rules_strings = []
            already_added_priv_rules = []

            # Statistics for the rule package
            rule_repo_statistics = {
                "total_rules": 0,
                "total_rules_skipped_age": 0,
                "total_rules_skipped_quality": 0,
                "total_rules_skipped_importance": 0,
                "total_rules_skipped_score": 0,
            }

            # Loop over the rule sets in the repository and modify the rules
            for rule_sets in repo['rules_sets']:
                # Debug output
                logging.debug("Writing YARA rules from rule set: %s", rule_sets['file_path'])
                # List of required private rules
                required_private_rules = []
                # Loop over the rules in the rule set
                for rule in rule_sets['rules']:

                    # Perform some check based on the meta data of the rule
                    skip_rule = False
                    skip_rule_reason = None
                    # Some values that will help with the decision whether to skip the rule
                    importance = None
                    # Loop over the metadata
                    for metadata in rule['metadata']:

                        # Age check ------------------------------------------------------
                        # Check if the rule has a minimum age
                        if "modified" in metadata:
                            rule_date = dateparser.parse(metadata['modified'])
                            # Check if the rule is old enough
                            if (datetime.datetime.now() - rule_date).days < rule_package['minimum_age']:
                                skip_rule = True
                                skip_rule_reason = "age"
                        # Check if the rule is younger than the maximum age
                        if "created" in metadata:
                            rule_date = dateparser.parse(metadata['created'])
                            # Check if the rule is old enough
                            if (datetime.datetime.now() - rule_date).days > rule_package['max_age']:
                                skip_rule = True
                                skip_rule_reason = "age"

                        # Score check ----------------------------------------------------
                        if "score" in metadata:
                            # Check if the rule has the require score
                            if metadata['score'] < rule_package['minimum_score']:
                                skip_rule = True
                                skip_rule_reason = "score"

                        # Quality check --------------------------------------------------
                        if "quality" in metadata:
                            # Check if the rule has the require quality
                            if metadata['quality'] < rule_package['minimum_quality']:
                                skip_rule = True
                                skip_rule_reason = "quality"
                        
                        # Importance check -----------------------------------------------
                        if "importance" in metadata:
                            importance = metadata['importance']

                    # If importance is set, check the importance level defined for the repo and overwrite
                    # the skip_rule variable if the importance of the rule is higher than the importance
                    # defined for the rule package
                    if importance is not None:
                        if importance >= rule_package['force_include_importance_level']:
                            skip_rule = False
                            skip_rule_reason = None
                            logging.debug("Forcing rule '%s' because of importance", rule['rule_name'])
                        if importance < rule_package['force_exclude_importance_level']:
                            skip_rule = True
                            skip_rule_reason = "importance"

                    # We skip private rules and add them only if other rules require them
                    if 'scopes' in rule:
                        if 'private' in rule['scopes']:
                            skip_rule = True

                    # Skip the rule if it doesn't match the minimum quality or age
                    if skip_rule:
                        logging.debug("Skipping rule '%s' because of %s", rule['rule_name'], skip_rule_reason)
                        if skip_rule_reason == "age":
                            rule_repo_statistics['total_rules_skipped_age'] += 1
                        elif skip_rule_reason == "quality":
                            rule_repo_statistics['total_rules_skipped_quality'] += 1
                        elif skip_rule_reason == "importance":
                            rule_repo_statistics['total_rules_skipped_importance'] += 1
                        elif skip_rule_reason == "score":
                            rule_repo_statistics['total_rules_skipped_score'] += 1
                        continue
                    else:
                        # Collect all private rules used in the accepted rules
                        if 'private_rules_used' in rule:
                            for priv_rule in rule['private_rules_used']:
                                if priv_rule not in required_private_rules:
                                    required_private_rules.append(priv_rule)

                    # Write the rule into the output file
                    repo_rules_strings.append(rebuild_yara_rule(rule))
                    rule_repo_statistics['total_rules'] += 1
                
                # Now we prepare the private rules
                # Loop over the required private rules
                for priv_rule in required_private_rules:
                    # Get the rule from the plyara object
                    priv_rule_string = rebuild_yara_rule(priv_rule["rule"])
                    # Append rule if it hasn't been added yet
                    if priv_rule["rule"]["rule_name"] not in already_added_priv_rules:
                        # Prepend the rule to the output string
                        repo_rules_strings.insert(0, priv_rule_string)
                        # Add the rule to the list of already added rules
                        already_added_priv_rules.append(priv_rule["rule"]["rule_name"])
                        rule_repo_statistics['total_rules'] += 1

            # Only write the rule set if there's at least one rule in the set
            if len(repo_rules_strings) > 0:
                # Prepend header to the output string
                repo_rule_set_header = YARA_FORGE_CONFIG['repo_header'].format(
                    repo_name=repo['name'],
                    repo_url=repo['url'],
                    retrieval_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                    repo_commit=repo['commit_hash'],
                    total_rules=rule_repo_statistics['total_rules'],
                    total_rules_skipped_age=rule_repo_statistics['total_rules_skipped_age'],
                    total_rules_skipped_quality=rule_repo_statistics['total_rules_skipped_quality'],
                    total_rules_skipped_importance=rule_repo_statistics['total_rules_skipped_importance'],
                    total_rules_skipped_score=rule_repo_statistics['total_rules_skipped_score'],
                    repo_license=repo['license']
                )
                # Append the rule set string to the list of rule set strings
                output_rule_set_strings.append(repo_rule_set_header)
                output_rule_set_strings.extend(repo_rules_strings)
            
            # Write the rule set statistics including total and skipped rules to the console
            logging.info("Rule set: '%s' Total rules: %d, Skipped: %d (age), %d (quality), %d (importance), %d (score)",
                            repo['name'],
                            rule_repo_statistics['total_rules'],
                            rule_repo_statistics['total_rules_skipped_age'],
                            rule_repo_statistics['total_rules_skipped_quality'],
                            rule_repo_statistics['total_rules_skipped_importance'],
                            rule_repo_statistics['total_rules_skipped_score'])

            # Add the repo statistics to the rule package statistics
            rule_package_statistics['repo_statistics'].append({
                "name": repo['name'],
                "total_rules": rule_repo_statistics['total_rules'],
                "total_rules_skipped_age": rule_repo_statistics['total_rules_skipped_age'],
                "total_rules_skipped_quality": rule_repo_statistics['total_rules_skipped_quality'],
                "total_rules_skipped_importance": rule_repo_statistics['total_rules_skipped_importance'],
                "total_rules_skipped_score": rule_repo_statistics['total_rules_skipped_score'],
            })

            # Add the repo statistics counters to the the rule package statistics
            rule_package_statistics['total_rules'] += rule_repo_statistics['total_rules']
            rule_package_statistics['total_rules_skipped_age'] += rule_repo_statistics['total_rules_skipped_age']
            rule_package_statistics['total_rules_skipped_quality'] += rule_repo_statistics['total_rules_skipped_quality']
            rule_package_statistics['total_rules_skipped_importance'] += rule_repo_statistics['total_rules_skipped_importance']
            rule_package_statistics['total_rules_skipped_score'] += rule_repo_statistics['total_rules_skipped_score']

        # Print the rule package statistics including total and skipped rules to the console
        logging.log(logging.INFO, "-------------------------------------------------------")
        logging.info("Rule package: '%s' Total rules: %d, Skipped: %d (age), %d (quality), %d (importance), %d (score)",
                     rule_package['name'],
                     rule_package_statistics['total_rules'],
                     rule_package_statistics['total_rules_skipped_age'],
                     rule_package_statistics['total_rules_skipped_quality'],
                     rule_package_statistics['total_rules_skipped_importance'],
                     rule_package_statistics['total_rules_skipped_score'])

        # Add the rule package statistics to the list of rule package statistics
        rule_package_statistics_set.append(rule_package_statistics)

        # Only write the rule file if there's at least one rule in all sets in the package
        if rule_package_statistics['total_rules'] > 0:
            with open(rule_file_path, "w", encoding="utf-8") as f:

                # Compose the package header and add the statistics on total rules and skipped rules
                rule_set_header = YARA_FORGE_CONFIG['rule_set_header'].format(
                    rule_package_name=rule_package['name'],
                    rule_package_description=rule_package['description'],
                    program_version=program_version,
                    yaraqa_commit=yaraqa_commit,
                    rule_package_minimum_quality=rule_package['minimum_quality'],
                    rule_package_force_include_importance_level=rule_package['force_include_importance_level'],
                    rule_package_force_exclude_importance_level=rule_package['force_exclude_importance_level'],
                    rule_package_minimum_age=rule_package['minimum_age'],
                    rule_package_minimum_score=rule_package['minimum_score'],
                    retrieval_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                    total_rules=rule_package_statistics['total_rules'],
                    total_rules_skipped_age=rule_package_statistics['total_rules_skipped_age'],
                    total_rules_skipped_quality=rule_package_statistics['total_rules_skipped_quality'],
                    total_rules_skipped_importance=rule_package_statistics['total_rules_skipped_importance'],
                    total_rules_skipped_score=rule_package_statistics['total_rules_skipped_score'],
                )

                logging.log(logging.INFO, "You can find more information about skipped files " \
                            "in the log file: yara-forge.log when you run it with --debug flag")

                # Prepend the header to the output rule set strings
                output_rule_set_strings.insert(0, rule_set_header)

                # Write the output rule set strings to the file
                f.write("".join(output_rule_set_strings))

        else:
            # remove the output file if it exists
            if os.path.exists(rule_file_path):
                os.remove(rule_file_path)

        # Add the name of the repo and the file path to the output file to the list
        package_files.append({
            "name": rule_package['name'],
            "file_path": rule_file_path,
        })

    # Write the rule package statistics as a markdown table to the build_stats.md file
    write_build_stats(rule_package_statistics_set)

    return package_files


def write_build_stats(rule_package_statistics_set):
    """
    Writes the rule package statistics as a markdown table to the build_stats.md file

    Create sections for each rule package.
    Then include a table and list each repo with the statistics.
    """

    # Create the build_stats.md file
    with open("build_stats.md", "w", encoding="utf-8") as f:
        # Write the header
        f.write("✨ This release contains the latest YARA rule sets from YARA Forge 🔨\n\n")
        f.write("# Build Statistics\n\n")
        # Loop over the rule packages
        for rule_package_statistics in rule_package_statistics_set:
            # Write the rule package name as a header
            f.write(f"## {rule_package_statistics['name']}\n\n")
            # Write the rule package statistics as a table
            f.write("| Repo | Total Rules | Skipped (Age) | Skipped (Quality) | Skipped (Importance) | Skipped (Score) |\n")
            f.write("| ---- | ----------- | ------------- | ----------------- | -------------------- | --------------- |\n")
            # Loop over the repos
            for repo_statistics in rule_package_statistics['repo_statistics']:
                f.write(f"| {repo_statistics['name']} | {repo_statistics['total_rules']} | {repo_statistics['total_rules_skipped_age']} | {repo_statistics['total_rules_skipped_quality']} | {repo_statistics['total_rules_skipped_importance']} | {repo_statistics['total_rules_skipped_score']} |\n")
            f.write("\n")

