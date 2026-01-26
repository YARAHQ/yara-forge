"""
This module contains functions for retrieving YARA rules from online repositories.
"""
import os
import shutil
import datetime
import logging
from urllib.parse import unquote
#from pprint import pprint
import plyara
from git import Repo


def process_yara_file(file_path, repo_folder, yara_rule_sets):
    # Debug output
    logging.debug("Found YARA rule file: %s", file_path)

    # Read the YARA file
    with open(file_path, "r", encoding="utf-8") as f:
        yara_file_content = f.read()
        # Parse the rules in the file
        try:
            # Get the rule file path in the repository
            relative_path = os.path.relpath(file_path, start=repo_folder)
            # Parse the YARA rules in the file
            yara_parser = plyara.Plyara()
            yara_rules = yara_parser.parse_string(yara_file_content)
            # Create a YARA rule set object
            yara_rule_set = {
                "rules": yara_rules,
                "file_path": relative_path,
            }
            # Debug output
            logging.debug("Found %d YARA rules in file: %s",
                          len(yara_rules), file_path)
            # Append to list of YARA rule sets
            yara_rule_sets.append(yara_rule_set)

        except Exception as e:
            print(e)
            logging.error("Skipping YARA rule in the following " \
                          "file because of a syntax error: %s ", file_path)


def retrieve_yara_rule_sets(repo_staging_dir, yara_repos):
    """
    Retrieves YARA rules from online repositories.
    """

    # The list of YARA rule sets of all repositories
    yara_rule_repo_sets = []

    # Check if the directory exists
    if os.path.exists(repo_staging_dir):
        # Remove the existing repo directory and all its contents
        shutil.rmtree(os.path.join(repo_staging_dir), ignore_errors=False)
    # Ensure the staging directory exists before cloning repositories
    os.makedirs(repo_staging_dir, exist_ok=True)

    # Loop over the repositories
    for repo in yara_repos:

        # Output the repository information to the console in a single line
        logging.info("Retrieving YARA rules from repository: %s", repo['name'])

        # Extract the owner and the repository name from the URL
        repo_url_parts = repo['url'].split("/")
        repo['owner'] = repo_url_parts[3]
        repo['repo'] = '/'.join(repo_url_parts[4:]).split(".")[0]

        # If the repository hasn't not been cloned yet, clone it
        if not os.path.exists(os.path.join(repo_staging_dir, repo['owner'], repo['repo'])):
            # Clone the repository
            repo_folder = os.path.join(repo_staging_dir, repo['owner'], repo['repo'])
            clone_env = os.environ.copy()
            # Skip LFS smudge to avoid downloading large binaries we do not need
            clone_env.setdefault("GIT_LFS_SKIP_SMUDGE", "1")
            # Partial clone keeps the checkout lean
            clone_options = ["--filter=blob:none"]
            # Sparse checkout will narrow paths further only if a given repository has a path configured (e.g., Malpedia)
            if 'path' in repo:
              clone_options.append("--sparse")
            repo_obj = Repo.clone_from(
                repo['url'],
                repo_folder,
                branch=repo['branch'],
                env=clone_env,
                multi_options=clone_options
            )
            # If a sub-path is configured, restrict checkout to that path to skip large folders
            if 'path' in repo:
                repo_obj.git.sparse_checkout('init', '--cone')
                # URL-decode the path before using it with git sparse-checkout
                decoded_path = unquote(repo['path'])
                repo_obj.git.sparse_checkout('set', decoded_path)
            repo['commit_hash'] = repo_obj.head.commit.hexsha
        else:
            # Repository already cloned - reuse it
            repo_folder = os.path.join(repo_staging_dir, repo['owner'], repo['repo'])
            repo_obj = Repo(repo_folder)
            repo['commit_hash'] = repo_obj.head.commit.hexsha
            # If this repo config has a path, add it to sparse checkout
            # (needed when multiple configs share the same git URL)
            if 'path' in repo:
                decoded_path = unquote(repo['path'])
                repo_obj.git.sparse_checkout('add', decoded_path)

        # Walk through the extracted folders and find a LICENSE file
        # and save it into the repository object
        repo['license'] = "NO LICENSE SET"
        repo['license_url'] = "N/A"
        for root, dir, files in os.walk(repo_folder):
            for file in files:
                if file == "LICENSE" or file == "LICENSE.txt" or file == "LICENSE.md":
                    file_path = os.path.join(root, file)
                    url_path = os.path.relpath(file_path, start=repo_folder)
                    if root == repo_folder:  # Check if the file is in the root directory
                        repo['license_url'] = f'{repo["url"]}/blob/{repo["commit_hash"]}/{url_path}'
                        with open(file_path, "r", encoding="utf-8") as f:
                            repo['license'] = f.read()
                        break # if we found the license in the root directory, we don't need to look further
                    elif 'license_url' not in repo:  # If the file is not in the root directory and no license has been found yet
                        repo['license_url'] = f'{repo["url"]}/blob/{repo["commit_hash"]}/{url_path}'
                        with open(file_path, "r", encoding="utf-8") as f:
                            repo['license'] = f.read()

        # Walk through the extracted folders and find all YARA files
        yara_rule_sets = []

        # Walk a sub folder if one is set in the config
        walk_folder = repo_folder
        if 'path' in repo:
            # URL-decode the path before using it
            decoded_path = unquote(repo['path'])
            walk_folder = os.path.join(repo_folder, decoded_path)
            # Print the processed folder
            logging.debug("Processing folder: %s", walk_folder)

        # Check if the path should be walked 
        recursive = True
        # Check if the path should be walked
        if 'recursive' in repo:
            recursive = repo['recursive']

        if recursive:
            # Walk the folder recursively
            for root, _, files in os.walk(walk_folder):
                for file in files:
                    if file.endswith(".yar") or file.endswith(".yara"):
                        file_path = os.path.join(root, file)
                        process_yara_file(file_path, repo_folder, yara_rule_sets)
        else:
            # Only walk the top-level directory
            for file in os.listdir(walk_folder):
                file_path = os.path.join(walk_folder, file)
                if os.path.isfile(file_path) and (file.endswith(".yar") or file.endswith(".yara")):
                    process_yara_file(file_path, repo_folder, yara_rule_sets)

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
            "license_url": repo['license_url'],
            "commit_hash": repo['commit_hash'],
            "retrieval_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "repo_path": repo_folder,
        }
        yara_rule_repo_sets.append(yara_rule_repo)

        # Output the number of YARA rules retrieved from the repository
        logging.info("Retrieved %d YARA rules from repository: %s",
                     len(yara_rule_sets), repo['name'])

    # Return the YARA rule sets
    return yara_rule_repo_sets
