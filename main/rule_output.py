"""
This module contains functions for writing YARA rules into separate files.
"""
import os
import logging
import datetime
import dateparser
from plyara.utils import rebuild_yara_rule


def write_yara_packages(processed_yara_repos, program_version, config):
    """
    Writes YARA rules into separate files.
    """

    # List of files that were written
    package_files = []

    # Loop over the rule packages
    for rule_package in config['yara_rule_packages']:

        # Statistics for the rule package
        rule_package_statistics = {
            "total_rules": 0,
            "total_rules_skipped_age": 0,
            "total_rules_skipped_quality": 0,
        }

        # Create the directory for the rule package
        package_dir = os.path.join("packages", rule_package['name'])
        if not os.path.exists(package_dir):
            os.makedirs(package_dir)
        # Create the rule file name
        rule_file_name = f"yara-rules-{rule_package['name']}.yar"
        # Create the rule file path
        rule_file_path = os.path.join(package_dir, rule_file_name)

        # Write information about the rule package, the output file name and the output file path to the console
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

            # Statistics for the rule package
            rule_set_statistics = {
                "total_rules": 0,
                "total_rules_skipped_age": 0,
                "total_rules_skipped_quality": 0,
            }

            # Loop over the rule sets in the repository and modify the rules
            for rule_sets in repo['rules_sets']:
                # Debug output
                logging.debug("Writing YARA rules from rule set: %s", rule_sets['file_path'])
                # Loop over the rules in the rule set
                for rule in rule_sets['rules']:

                    # Perform some check based on the meta data of the rule
                    skip_rule = False
                    # Loop over the metadata
                    for metadata in rule['metadata']:

                        # Age check ---------------------------------------------------------------
                        # Check if the rule has a minimum age
                        if "modified" in metadata:
                            rule_date = dateparser.parse(metadata['modified'])
                            # Check if the rule is old enough
                            if (datetime.datetime.now() - rule_date).days < rule_package['minimum_age']:
                                logging.debug("Skipping rule %s because it is too young: %s", rule['rule_name'], metadata['date'])
                                skip_rule = True
                                rule_set_statistics['total_rules_skipped_age'] += 1

                        # Quality check ---------------------------------------------------------------
                        if "quality" in metadata:
                            # Check if the rule has the require quality
                            if metadata['quality'] < rule_package['minimum_quality']:
                                logging.debug("Skipping rule %s because of insufficient quality score: %d", rule['rule_name'], metadata['quality'])
                                skip_rule = True
                                rule_set_statistics['total_rules_skipped_quality'] += 1

                    if skip_rule:
                        continue

                    # Write the rule into the output file
                    repo_rules_strings.append(rebuild_yara_rule(rule))
                    rule_set_statistics['total_rules'] += 1

            # Only write the rule set if there's at least one rule in the set
            if len(repo_rules_strings) > 0:
                # Prepend header to the output string
                repo_rule_set_header = config['repo_header'].format(
                    repo_name=repo['name'],
                    repo_url=repo['url'],
                    retrieval_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                    total_rules_skipped_age=rule_set_statistics['total_rules_skipped_age'],
                    total_rules_skipped_quality=rule_set_statistics['total_rules_skipped_quality'],
                    repo_license=repo['license']
                )
                # Append the rule set string to the list of rule set strings
                output_rule_set_strings.append(repo_rule_set_header)
                output_rule_set_strings.extend(repo_rules_strings)
                # Write the rule set statistics including total and skipped rules to the console
                logging.info("Rule set: '%s' Total rules: %d, Skipped: %d (age), %d (quality)", repo['name'], rule_set_statistics['total_rules'], rule_set_statistics['total_rules_skipped_age'], rule_set_statistics['total_rules_skipped_quality'])

        # Add the repo statistics to the the rule package statistics
        rule_package_statistics = {key: rule_package_statistics[key] + rule_set_statistics.get(key, 0) for key in rule_package_statistics}

        # Write the rule package statistics including total and skipped rules to the console
        logging.log(logging.INFO, "------------------------------------------------------------------------")
        logging.info("Rule package: '%s' Total rules: %d, Skipped: %d (age), %d (quality)", rule_package['name'], rule_package_statistics['total_rules'], rule_package_statistics['total_rules_skipped_age'], rule_package_statistics['total_rules_skipped_quality'])

        # Only write the rule file if there's at least one rule in the set
        if rule_package_statistics['total_rules'] > 0:
            with open(rule_file_path, "w", encoding="utf-8") as f:

                # Compose the package header and add the statistics on total rules and skipped rules
                rule_set_header = config['rule_set_header'].format(
                    rule_package_name=rule_package['name'],
                    rule_package_description=rule_package['description'],
                    program_version=program_version,
                    rule_package_minimum_quality=rule_package['minimum_quality'],
                    rule_package_minimum_age=rule_package['minimum_age'],
                    retrieval_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                    total_rules_skipped_age=rule_package_statistics['total_rules_skipped_age'],
                    total_rules_skipped_quality=rule_package_statistics['total_rules_skipped_quality'],
                )

                logging.log(logging.INFO, "You can find more information about skipped files in the log file: yara-forge.log when you run it with --debug flag")

                # Prepend the header to the output rule set strings
                output_rule_set_strings.insert(0, rule_set_header)

                # Write the output rule set strings to the file
                f.write("".join(output_rule_set_strings))

        # Add the name of the repo and the file path to the output file to the list
        package_files.append({
            "name": rule_package['name'],
            "file_path": rule_file_path,
        })

        return package_files