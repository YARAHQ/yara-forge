"""
This file contains functions that process the YARA rules.
"""
import logging
import re
import uuid
from pprint import pprint
import yaml
import dateparser
from plyara.utils import generate_hash
from git import Repo

# Date Lookup Cache
date_lookup_cache = {}

# Private YARA rules
private_rule_mapping = []

def process_yara_rules(yara_rule_repo_sets, YARA_FORGE_CONFIG):
    """
    Processes the YARA rules
    """

    # Logic hash list to avoid duplicates
    logic_hash_list = {}

    # Loop over the repositories
    for repo in yara_rule_repo_sets:

        # Rule set identifier
        rule_set_id = repo['name'].replace(" ", "_").replace("-", "_").upper()

        # Debug output
        logging.info("Processing YARA rules from repository: %s", repo['name'])

        # Loop over the rule sets in the repository and modify the rules
        num_rules = 0
        for rules in repo['rules_sets']:
            # Debug output
            logging.debug("Processing YARA rules from rule set: %s", rules['file_path'])
            # Rules that we want to keep
            kept_rules = []
            # Loop over each of the rules and modify them
            for rule in rules['rules']:
                # Debug output
                logging.debug("Processing YARA rule: %s", rule['rule_name'])

                # Rule Meta Data Modifications ----------------------------------------------

                # Check if the rule is a private rule
                is_private_rule = False
                if 'scopes' in rule:
                    if 'private' in rule['scopes']:
                        is_private_rule = True

                # Add metadata to rules that don't have any
                if 'metadata' not in rule:
                    rule['metadata'] = []

                # Calculate the logic hash
                logic_hash = generate_hash(rule)

                # Duplicate Name Check
                # If the rule name already exists in the list, append a number to it
                if rule['rule_name'] in logic_hash_list.values():
                    # Get the number of times the rule name already exists in the list
                    num_rule_name = list(logic_hash_list.values()).count(rule['rule_name'])
                    # Append the number to the rule name
                    rule['rule_name'] = f"{rule['rule_name']}_{num_rule_name}"

                # Duplicate Content Check
                # Check if the rule is a duplicate  (based on the logic hash)
                if logic_hash in logic_hash_list and not is_private_rule:
                    logging.info("Skipping rule '%s > %s' because it has the same logic hash as '%s'", 
                                 repo['name'], rule['rule_name'], logic_hash_list[logic_hash])
                    continue
                # Register the logic hash
                logic_hash_list[logic_hash] = rule['rule_name']
                modify_meta_data_value(rule['metadata'], 'logic_hash', logic_hash)

                # Calculate a UUID for the rule hash
                rule_uuid = generate_uuid_from_hash(logic_hash)
                align_yara_rule_uuid(rule['metadata'], rule_uuid)

                # Modifying existing meta data values ---------------------------------------

                # Modify the rule references
                rule['metadata'] = align_yara_rule_reference(rule['metadata'], repo['url'])

                # Modify the rule date
                rule['metadata'] = align_yara_rule_date(rule['metadata'],
                                                        repo['repo_path'],
                                                        rules['file_path'])

                # Modify the rule hashes
                rule['metadata'] = align_yara_rule_hashes(rule['metadata'])

                # # Modify the rule description
                rule['metadata'] = align_yara_rule_description(rule['metadata'], repo['name'])

                # Modify the rule author
                rule['metadata'] = align_yara_rule_author(rule['metadata'], repo['author'])

                # Add tags based on meta data values and condition elements
                rule = add_tags_to_rule(rule)

                # Add a score based on the rule quality and meta data keywords
                rule_score = evaluate_yara_rule_score(rule, YARA_FORGE_CONFIG)
                modify_meta_data_value(rule['metadata'], 'score', rule_score)

                # Get a custom importance score if available
                custom_importance_score = retrieve_custom_importance_score(repo['name'], rules['file_path'], rule['rule_name'])
                if custom_importance_score:
                    modify_meta_data_value(rule['metadata'], 'importance', custom_importance_score)
                    logging.debug("Custom importance score for rule %s is %d", rule['rule_name'], custom_importance_score)

                # Adding additional meta data values ----------------------------------------
                # Add a quality value based on the original repo
                # a quality reduction is evaluated later in the process - this is just the base value
                # for that calculation
                modify_meta_data_value(rule['metadata'], 'quality', repo['quality'])

                # Modify the rule name
                rule_name_old = rule['rule_name']
                rule_name_new = align_yara_rule_name(rule['rule_name'], rule_set_id)
                # If the rule is private, add the _PRIVATE suffix and
                if is_private_rule:
                    rule_name_new = f"{rule_name_new}_PRIVATE"
                    # Add the rule to the private rule mapping
                    private_rule_mapping.append({
                        "repo": rule_set_id,
                        "old_name": rule_name_old,
                        "new_name": rule_name_new,
                        "rule": rule
                    })
                # Set the new rule name
                rule['rule_name'] = rule_name_new

                # Check if the rule uses private rules
                private_rules_used = check_rule_uses_private_rules(rule_set_id, rule, private_rule_mapping)
                if private_rules_used:
                    # Change the condition terms of the rule to align them with
                    # the new private rule names
                    rule['condition_terms'] = adjust_identifier_names(
                        rule_set_id,
                        rule['condition_terms'],
                        private_rules_used)
                # Add the private rules used to the rule
                rule['private_rules_used'] = private_rules_used
                logging.debug("Private rules used: %s", private_rules_used)

                # Add a rule source URL to the original file
                modify_meta_data_value(
                    rule['metadata'], 'source_url',
                    (
                        f'{repo["url"]}/blob/{repo["commit_hash"]}/{rules["file_path"]}'
                        f'#L{rule["start_line"]}-L{rule["stop_line"]}'
                    )
                )

                # Add license URL
                modify_meta_data_value(rule['metadata'], 'license_url', repo['license_url'])

                # Sort the meta data values
                rule['metadata'] = sort_meta_data_values(rule['metadata'], YARA_FORGE_CONFIG)

                # We keep the rule
                kept_rules.append(rule)

            # Count the number of rules
            num_rules += len(kept_rules)
            # Now we replace the rules
            rules['rules'] = kept_rules

        # Info output about the number of rules in the repository
        logging.info("Normalized %d rules from repository: %s", num_rules, repo['name'])

    return yara_rule_repo_sets


def add_tags_to_rule(rule):
    """
    Add tags to a rule based on meta data values and condition elements
    """
    # List of tags to add
    tags_to_add = []
    # List of possible tags
    tag_names = ['tag', 'tags', 'category', 'categories', 'type', 'types', 'family', 'families',
                 'malware', 'threat', 'threats', 'threat_type', 'actor', 'threat_actor', 'threat_actors',
                 'threat_types', 'threat_category', 'threat_categories', 'threat_family',
                 'threat_families', 'threat_group', 'threat_groups', 'scan_context',
                 'malware_type', 'mitre_attack', 'mitre_attack_technique', 'mitre_attack_techniques'
                 'attack_technique', 'attack_techniques', 'attack', 'attacks', 'attack_type']
    # Regular expressions to extract other tags from the description
    tag_regexes = [
        r'CVE-\d{4}-\d{4,7}', # CVE IDs
        r'T[0-9]{4}', # MITRE ATT&CK Technique IDs
    ]
    # Join the list of regexes with an OR operator and compile the regex
    tag_regex = re.compile(r'(?i)\b(%s)\b' % "|".join(tag_regexes))
    # List of values to ignore
    ignore_values = ['N/A', 'n/a', 'na', 'NA', 'unknown', 'Unknown', '', ' ']
    # List of possible condition elements
    condition_contents = {
        "FILE": ['uint8(0)', 'uint16(0)', 'uint32(0)', 'uint16be(0)', 'uint32be(0)', 
                 ' at 0 ', 'filesize'],
        # "MEMORY": [' or all of them']
    }
    condition_ends = {
        "FILE": [' at 0'],
        # "MEMORY": [' or any of them', ' or all of them', ' or 1 of them'],
    }
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule['metadata'].copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible tag names, then we found the tag
            if key.lower() in tag_names:
                # Check if the value is a list
                if isinstance(value, list):
                    # Loop over the list
                    for tag in value:
                        # Add the tag to the list of tags to add
                        tags_to_add.append(tag)
                # If the value is not a list, we just add it
                else:
                    # If the value contains a comma, we split it
                    if "," in value:
                        # Split the value
                        value = value.split(",")
                        # Loop over the values
                        for tag in value:
                            # Add the tag to the list of tags to add
                            tags_to_add.append(tag.strip())
                    # Add the tag to the list of tags to add
                    else:
                        tags_to_add.append(value)

    # Remove tags that are in the ignore list
    tags_to_add = [tag for tag in tags_to_add if tag not in ignore_values]

    # Extractions from meta data ----------------------------------------------
    # Extract tags from the description
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible tag names, then we found the tag
            if key.lower() == "description":
                # Extract the tags from the description
                tags_from_description = tag_regex.findall(value)
                # Add the tags to the list of tags to add
                tags_to_add.extend(tags_from_description)

    # Condition tags ----------------------------------------------------------
    # If one of the values is in the condition contents we add a specific tag
    for condition_mapping in condition_contents.items():
        # Get the element
        tag = condition_mapping[0]
        # Get the condition terms
        condition_terms = condition_mapping[1]
        # Check if the element is in the condition terms
        for term in condition_terms:
            if term in rule['raw_condition']:
                # Add the element to the list of tags to add
                tags_to_add.append(tag)
    # If one of the is how the condition ends we add a specific tag
    for condition_mapping in condition_ends.items():
        # Get the element
        tag = condition_mapping[0]
        # Get the condition terms
        condition_terms = condition_mapping[1]
        # Check if the element is in the condition terms
        for term in condition_terms:
            if rule['raw_condition'].endswith(term):
                # Add the element to the list of tags to add
                tags_to_add.append(tag)

    # Clean up the tags ----------------------------------------------------------
    # Remove all duplicates from the tags list 
    tags_to_add = list(dict.fromkeys(tags_to_add))
    # We uppercase all the tags
    tags_to_add = [tag.upper() for tag in tags_to_add]
    # We also modify the existing tags field in the meta data
    rule['metadata'] = modify_meta_data_value(rule['metadata'], 'tags', ", ".join(tags_to_add))
    # Remove symbols that are not allowed in tags (only alphanumeric characters and
    # underscores are allowed), replace every other character with an underscore using a regex
    tags_to_add = [re.sub(r'[^a-zA-Z0-9_]', '_', tag) for tag in tags_to_add]
    # Add the tags to the rule if the field already exist
    if 'tags' in rule:
        rule['tags'].extend(tags_to_add)
    # If the field doesn't exist, we create it
    else:
        rule['tags'] = tags_to_add
    return rule

def retrieve_custom_importance_score(repo_name, file_path, rule_name):
    """
    Retrieves a custom importance score for a rule
    """
    # Read the scores from the YAML file named yara-forge-custom-scoring.yml
    with open('yara-forge-custom-scoring.yml', 'r', encoding='utf-8') as f:
        custom_scoring = yaml.safe_load(f)

        logging.debug("Checking custom importance score for rule %s in file %s in repo %s", rule_name, file_path, repo_name)
        
        # Loop over the rules in the YAML file
        for importance_score in custom_scoring['importance-scores']:
            # Marker that indicates if every element of the rule matched
            rule_elements_matched = False
            for rule_field, rule_value in importance_score['rule'].items():
                if rule_field == "name":
                    if rule_name.startswith(rule_value):
                        logging.debug("Rule name %s starts with %s", rule_name, rule_value)
                        rule_elements_matched = True
                    else:
                        rule_elements_matched = False
                        break
                elif rule_field == "file":
                    if file_path.endswith(rule_value):
                        logging.debug("File path %s ends with %s", file_path, rule_value)
                        rule_elements_matched = True
                    else:
                        rule_elements_matched = False
                        break
                elif rule_field == "repo":
                    if repo_name == rule_value:
                        logging.debug("Repo name %s matches %s", repo_name, rule_value)
                        rule_elements_matched = True
                    else:
                        rule_elements_matched = False
                        break
            # If all elements of the rule matched, we return the importance score
            if rule_elements_matched:
                return importance_score['importance']
    return None


def sort_meta_data_values(rule_meta_data, YARA_FORGE_CONFIG):
    """
    Sort the meta data values
    """
    # Fixed order of meta data values
    fixed_order = YARA_FORGE_CONFIG['meta_data_order']

    # We loop over the list of dicts and sort them by key according to our fixed_order
    rule_meta_data.sort(key=lambda x: fixed_order.index(list(x.keys())[0]) if list(x.keys())[0] in fixed_order else len(fixed_order))

    return rule_meta_data

def adjust_identifier_names(repo_name, condition_terms, private_rules_used):
    """
    Adjust the identifier names of a rule to align them with the new private rule names
    """
    # Loop over the private rules used
    for private_rule in private_rules_used:
        # Loop over the condition terms
        for i, condition_term in enumerate(condition_terms):
            # Check if the condition term is the private rule
            if condition_term == private_rule['old_name'] and private_rule['repo'] == repo_name:
                # Replace the condition term with the new private rule name
                condition_terms[i] = private_rule['new_name']
    return condition_terms


def check_rule_uses_private_rules(repo_name, rule, ext_private_rule_mapping):
    """
    Check if the rule uses private rules
    """
    # List of private rules used
    private_rules_used = []
    # Loop over the private rules
    for private_rule in ext_private_rule_mapping:
        # Check if the rule uses the private rule
        if private_rule['old_name'] in rule['condition_terms'] and private_rule['repo'] == repo_name:
            # Only add that rule as long as it is not already in the list
            if private_rule not in private_rules_used:
                # Add the private rule to the list of private rules used
                private_rules_used.append(private_rule)
    return private_rules_used


def align_yara_rule_description(rule_meta_data, repo_description):
    """
    Check if there's a description set in the YARA rule and if not, add the repository description
    """
    # List of possible description names
    description_names = ['description', 'desc', 'details', 'information', 'info',
                         'notes', 'abstract', 'explanation', 'rationale']
    description_values_prefixes = ['Detects ']
    threat_names = ['threat_name', 'threat', 'malware', 'mal', 'malware_name', 'mal_name',
                    'threat_type', 'threat_category', 'threat_family', 'threat_group',]
    # Look for the description in the rule meta data
    description_found = False
    description_value = f"No description has been set in the source file - {repo_description}"
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible description names, then we found the description
            if key in description_names:
                description_found = True
                description_value = value
                # Remove the description from the original meta data
                rule_meta_data.remove(meta_data)
            # If the value starts with one of the prefixes, then we found the description
            elif isinstance(value, str) and value.startswith(tuple(description_values_prefixes)):
                description_found = True
                description_value = value
                # Remove the description from the original meta data
                rule_meta_data.remove(meta_data)
        # If we couldn't find a description so far, we use the first threat name we can find
        if not description_found:
            for key, value in meta_data.items():
                # If we can find a threat name, we use it to formulate a description
                if key.lower() in threat_names:
                    description_found = True
                    # If the threat name contains a period or dash we replace it and
                    # put the original name in brackets
                    description_value = f"Detects {value.replace('.', ' ').replace('-', ' ').title()} ({value})"
                    # Remove the description from the original meta data
                    rule_meta_data.remove(meta_data)
    # Lower the quality score if the descriptions hasn't been set
    if not description_found:
        modify_yara_rule_quality(rule_meta_data, -5)
    # Set the new description
    rule_meta_data.append({'description': description_value})
    return rule_meta_data


def align_yara_rule_hashes(rule_meta_data):
    """
    Check for all the hash values in the meta data and align them to the key value 'hash'
    """
    # List of possible hash names
    hash_names = ['hash', 'hashes', 'md5', 'sha1', 'sha256', 'sha512', 'sha-1',
                  'sha-256', 'sha-512', 'sha_256', 'sha_1', 'sha_512', 'md5sum',
                  'sha1sum', 'sha256sum', 'sha512sum', 'md5sums', 'sha1sums', 'sha256sums',
                  'sha512sums', 'reference_sample', 'sample', 'original_sample_sha1']
    # Look for the hashes in the rule meta data
    hashes_found = False
    hashes_values = []
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for mdata in meta_data_copy:
        for key, value in mdata.items():
            # If the key is in the list of possible hash names, then we found the hashes
            if key.lower() in hash_names:
                hashes_found = True
                hashes_values.append(value.lower())
                # Remove the hashes from the original meta data
                rule_meta_data.remove(mdata)
    # If the hashes are found, modify them
    if hashes_found:
        for value in hashes_values:
            rule_meta_data.append({'hash': value})
    return rule_meta_data


def modify_yara_rule_quality(rule_meta_data, reduction_value):
    """
    Modifies the quality score of a YARA rule.
    """
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for mdata in meta_data_copy:
        for k, _ in mdata.items():
            # If the key is in the meta data, then we modify it
            if k == "quality":
                mdata[k] += reduction_value
                return meta_data_copy
    return rule_meta_data


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


# Evaluate the YARA rule score
def evaluate_yara_rule_score(rule, YARA_FORGE_CONFIG):
    """
    Evaluate the YARA rule score
    
    We fist set the base score from the config
    
    We then take the next best score based on this order:
    - Custom score from the YAML file
    - Predefined score from the meta data
    - Meta data score based on keywords

    If we can't find a score, we use the base score
    """
    # Score for the rule quality
    rule_score = YARA_FORGE_CONFIG['rule_base_score']

    # If a manual score has been set in the YAML file we use that
    custom_score = retrieve_custom_score(rule)
    if custom_score > 0:
        logging.debug("Rule '%s' has a custom score of %d", rule['rule_name'], custom_score)
        return custom_score

    # Check if the rule already has a score
    for meta_data in rule['metadata']:
        for key, value in meta_data.items():
            if key == 'score':
                # If the rule already has a score, we use that
                return value

    # Score for the rule meta data
    meta_data_rule_score = evaluate_yara_rule_meta_data(rule)
    if meta_data_rule_score > 0:
        logging.debug("Rule '%s' has a meta data score of %d", rule['rule_name'], meta_data_rule_score)
        return meta_data_rule_score
    
    return rule_score


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
    return 0


def evaluate_yara_rule_meta_data(rule):
    """
    Evaluate the score modifier based on the rule meta data
    """
    # List of possible meta data keywords
    meta_data_keywords_suspicious = ['suspicious']
    # List of possible meta data keywords
    meta_data_keywords_hunting = ['hunting', 'experimental', 'test', 'testing', 'false positive',
                                     'unstable', 'untested', 'unverified', 'unreliable', 
                                     'unconfirmed']
    # Check if one of the keywords appears in the meta data values
    for meta_data in rule['metadata']:
        for _, value in meta_data.items():
            if isinstance(value, str) and value.lower() in meta_data_keywords_suspicious:
                return 65
            if isinstance(value, str) and value.lower() in meta_data_keywords_hunting:
                return 50
    # Check if one of the keywords appears in the rule name
    for keyword in meta_data_keywords_suspicious:
        if keyword in rule['rule_name'].lower():
            return 65
    for keyword in meta_data_keywords_hunting:
        if keyword in rule['rule_name'].lower():
            return 50
    return 0


def align_yara_rule_author(rule_meta_data, repo_author):
    """
    Change YARA rule author
    """
    # List of possible author names
    author_names = ['author', 'authors', 'writer', 'creator', 'created_by', 'created_by',
                    'copyright', 'made_by', 'contributor', 'contributed_by']
    # Look for the author in the rule meta data
    author_found = False
    author_value = ""
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible author names, then we found the author
            if key in author_names:
                author_found = True
                author_value = value
                # Remove the author from the original meta data
                rule_meta_data.remove(meta_data)
    # If the author is found, modify it
    if author_found:
        rule_meta_data.append({'author': author_value})
    # If the author is not found, add it
    if not author_found:
        rule_meta_data.append({'author': repo_author})
    return rule_meta_data


def align_yara_rule_uuid(rule_meta_data, uuid):
    """
    Change YARA rule UUID
    """
    # List of possible author names
    uuid_names = ['uuid', 'id', 'rid', 'rule_id', 'rule_uuid', 'ruleid',
                  'ruleuuid', 'identifier', 'rule_identifier']
    # Look for the author in the rule meta data
    uuid_value = uuid
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible author names, then we found the author
            if key in uuid_names:
                # Check if the value is a valid UUIDv5
                if is_valid_uuidv5(value):
                    # If the value is a valid UUID, we use it
                    uuid_value = value
                    # Remove the author from the original meta data
                    rule_meta_data.remove(meta_data)
                else:
                    # If the value is not a valid UUID, we use the hash of the rule
                    logging.debug("The value '%s' is not a valid UUID. Using our UUID instead "
                                  "and renaming the old ID to 'orig_id' if the field was 'id'.", 
                                  value)
                    # If the field was 'id', we rename it to 'orig-id'
                    if key == 'id':
                        logging.debug("Renaming the old ID to 'orig_id'.")
                        modify_meta_data_value(rule_meta_data, 'orig_id', value)
                        rule_meta_data.remove(meta_data)
                    # else, we just leave everything as it is and do nothing with the value

    # We add the UUID to the rule meta data
    rule_meta_data.append({'id': uuid_value})
    return rule_meta_data


def is_valid_uuidv5(value):
    """
    Check if the value is a valid UUID
    """
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False

def align_yara_rule_name(rule_name, rule_set_id):
    """
    Change YARA rule name
    """
    # New name elements
    new_name_elements = []
    # Add the rule set identifier
    new_name_elements.append(rule_set_id)
    # Dissect the rule name
    name_elements = rule_name.split("_")
    # Change every element of the rule
    for element in name_elements:
        # If the element is already all uppercase, add it to the new name
        if element.isupper():
            new_name_elements.append(element)
            continue
        # If the element is all lowercase or anything else, then title case it
        new_name_elements.append(element.title())
    return "_".join(new_name_elements)


def align_yara_rule_reference(rule_meta_data, rule_set_url):
    """
    Modify the YARA rule references
    """
    # List of possible reference names
    other_ref_names = ['reference', 'references', 'ref', 'url', 'source', 'link',
                       'website', 'webpage', 'report']
    other_indicators = ['http://', 'https://']
    # Look for the reference in the rule meta data
    reference_found = False
    reference_value = ""
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible reference names, then we found the reference
            if key in other_ref_names:
                reference_found = True
                reference_value = value
                # Remove the reference from the original meta data
                rule_meta_data.remove(meta_data)
            # If the value starts with http:// or https://, then we found the reference
            elif isinstance(value, str) and value.startswith(tuple(other_indicators)):
                reference_found = True
                reference_value = value
                # Remove the reference from the original meta data
                rule_meta_data.remove(meta_data)
    # If the reference is found, modify it
    if reference_found:
        rule_meta_data.append({'reference': reference_value})
    # If the reference is not found, add it
    if not reference_found:
        rule_meta_data.append({'reference': rule_set_url})
    return rule_meta_data


def align_yara_rule_date(rule_meta_data, repo_path, file_path):
    """
    Modify the YARA rule date
    """
    # List of possible date names
    date_names = ['date', 'created', 'created_at', 'creation_date', 'creation_time',
                  'creation', 'timestamp', 'time', 'datetime']
    modified_names = ['modified', 'last_modified', 'last_modified_at', 'last_modified_date',
                      'last_change', 'last_change_date', 'last_update', 'last_update_date',
                      'updated', 'updated_at', 'updated_date', 'updated_timestamp']
    # Look for the date in the rule meta data
    date_found = False

    # GIT HISTORY -----------------------------------------------------------
    # We retrieve values from the git history that we can use in case we don't
    # find these values in the meta data

    # Check if the date is in the cache
    if file_path in date_lookup_cache:
        # Debug info
        logging.debug("Retrieved date info for file %s from cache.", file_path)
        (git_creation_date, git_modification_date) = date_lookup_cache[file_path]
    else:
        # Getting the last modification date of the rule file from the git log
        # (this is not completely reliable, but better than nothing)
        (git_creation_date, git_modification_date) = get_rule_age_git(repo_path, file_path)
        if git_creation_date:
            # Add the date to the cache
            date_lookup_cache[file_path] = (git_creation_date, git_modification_date)

    # CREATION DATE -----------------------------------------------------------
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we loop over the copy
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible date names, then we found the date
            if key in date_names:
                date_found = True
                date_created = dateparser.parse(value)
                if date_created:
                    # Remove the date from the original meta data
                    rule_meta_data.remove(meta_data)
                    rule_meta_data.append({'date': date_created.strftime("%Y-%m-%d")})

    # If the date is not found, try to get it from any of the meta data fields
    if not date_found:
        # Check if we find the date in a different value by looking for fields that contain a date
        for meta_data in meta_data_copy:
            for key, value in meta_data.items():
                # If the value contains a date, then we found the date
                if isinstance(value, str) and dateparser.parse(value):
                    date_found = True
                    date_created = dateparser.parse(value)
                    if date_created:
                        # Remove the date from the original meta data
                        rule_meta_data.remove(meta_data)
                        rule_meta_data.append({'date': date_created.strftime("%Y-%m-%d")})

    # If the date was still not found, we try to get the date from the git log
    if not date_found:
        # Add the date to the rule meta data
        rule_meta_data.append({'date': git_creation_date.strftime("%Y-%m-%d")})

    # MODIFICATION DATE -----------------------------------------------------------
    # We create a copy so that we can delete elements from the original
    meta_data_copy = rule_meta_data.copy()
    # Now we check for a modification date
    modified_found = False
    for meta_data in meta_data_copy:
        for key, value in meta_data.items():
            # If the key is in the list of possible date names, then we found the date
            if key in modified_names:
                modified_value = dateparser.parse(value)
                if modified_value:
                    modified_found = True
                    # Remove the date from the original meta data
                    rule_meta_data.remove(meta_data)
    # If the modified date was found and removed, add the new streamlined date value
    if modified_found:
        rule_meta_data.append({'modified': modified_value.strftime("%Y-%m-%d")})

    # If the modified date was still not found, we try to get the date from the git log
    if not modified_found:
        # Add the modified ate to the rule meta data
        rule_meta_data.append({'modified': git_modification_date.strftime("%Y-%m-%d")})

    return rule_meta_data


def get_rule_age_git(repo_path, file_path):
    """
    Get the last modification date of the rule file from the git log
    """

    # Initialize the repository object
    repo = Repo(repo_path)

    logging.debug("Repo path '%s'", repo_path)
    logging.debug("Retrieving date info for file '%s' from git log.", file_path)

    # Iterate over the commits that modified the file, and take the first one
    commits = list(repo.iter_commits(paths=file_path, max_count=1))
    if commits:
        first_commit = commits[-1]
        last_commit = commits[0]
        # Extract the datetime of the first commit that added the file
        creation_date = first_commit.committed_datetime
        # Extract the datetime of the last commit that modified the file
        modification_date = last_commit.committed_datetime
        logging.debug("Retrieved date info for file %s from git log. "
                      " Creation date: %s, Last modification: %s", 
                      file_path, creation_date, modification_date)
        # Return the date in the format YYYY-MM-DD
        return (creation_date, modification_date)
    print(f"No commits found for the file {file_path}.")
    # If we couldn't find any commits, we return the creation date of the repository
    repo_creation_date = list(repo.iter_commits(max_count=1))[-1].committed_datetime
    return (repo_creation_date, repo_creation_date)


def generate_uuid_from_hash(hash):
    """
    Generate a UUID from a hash
    """
    return uuid.uuid5(uuid.NAMESPACE_DNS, hash)
