import plyara
import requests
import pprint
import dateparser


# Date Lookup Cache
date_lookup_cache = {}


# Process the YARA rules
def process_yara_rules(yara_rule_repo_sets, debug=False):
   # Loop over the repositories
   for repo in yara_rule_repo_sets:
      # Rule set identifier
      rule_set_id = repo['name'].replace(" ", "_").upper()
      # Debug output
      if debug:
         print("Processing YARA rules from repository: %s" % repo['name'])
      # Loop over the rule sets in the repository and modify the rules
      for rules in repo['rules_sets']:
         # Debug output
         if debug:
            print("Processing YARA rules from rule set: %s" % rules['file_path'])
         # Loop over each of the rules and modify them
         for rule in rules['rules']:
            # Debug output
            if debug:
               print("Processing YARA rule: %s" % rule['rule_name'])
            # Modify the rule name
            rule['rule_name'] = process_yara_rule_name(rule['rule_name'], rule_set_id)
            # Modify the rule references
            rule['metadata'] = process_yara_rule_reference(rule['metadata'], repo['url'])
            # Modify the rule date
            rule['metadata'] = process_yara_rule_date(rule['metadata'], repo['owner'], repo['repo'], repo['branch'], rules['file_path'])
            # # Modify the rule tags
            # rule['metadata'] = process_yara_rule_tags(rule['metadata'], repo['tags'])
            # # Modify the rule description
            # rule['metadata'] = process_yara_rule_description(rule['metadata'], repo['description'])
            # Modify the rule author
            rule['metadata'] = process_yara_rule_author(rule['metadata'], repo['author'])
            # # Modify the rule license
            # rule['metadata'] = process_yara_rule_license(rule['metadata'], repo['license'])
            # # Modify the rule version
            # rule['metadata'] = process_yara_rule_version(rule['metadata'], repo['version'])
            # # Modify the rule strings
            # rule['strings'] = process_yara_rule_strings(rule['strings'])
            # # Modify the rule condition
            # rule['condition'] = process_yara_rule_condition(rule['condition'])
   return yara_rule_repo_sets


# Change YARA rule author
def process_yara_rule_author(rule_meta_data, repo_author):
   # List of possible author names
   author_names = ['author', 'authors', 'writer', 'creator', 'created_by', 'created_by', 'copyright', 'made_by']
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


# Change YARA rule name
def process_yara_rule_name(rule_name, rule_set_id):
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
      else:
         new_name_elements.append(element.title())
   return "_".join(new_name_elements)


# Modify the YARA rule references
def process_yara_rule_reference(rule_meta_data, rule_set_url):
   # List of possible reference names
   other_ref_names = ['reference', 'references', 'ref', 'url', 'source', 'link', 'website', 'webpage']
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


# Modify the YARA rule date
def process_yara_rule_date(rule_meta_data, owner, repo, branch, file_path):
   # List of possible date names
   date_names = ['date', 'created', 'created_at', 'creation_date', 'creation_time', 'creation', 'timestamp', 'time', 'datetime']
   # Look for the date in the rule meta data
   date_found = False
   date_value = ""
   # We create a copy so that we can delete elements from the original
   meta_data_copy = rule_meta_data.copy()
   # Now we loop over the copy
   for meta_data in meta_data_copy:
      for key, value in meta_data.items():
         # If the key is in the list of possible date names, then we found the date
         if key in date_names:
            date_found = True
            date_value = dateparser.parse(value)
            # Remove the date from the original meta data
            rule_meta_data.remove(meta_data)
   # If the date is found, modify it  
   if date_found:
      rule_meta_data.append({'date': date_value.strftime("%Y-%m-%d")}) 
   # If the date is not found, add it
   if not date_found:
      # Check if the date is in the cache
      if file_path in date_lookup_cache:
         # Debug info
         print(f"Getting the date from the cache for file: {file_path}")
         date_value = date_lookup_cache[file_path]
      else:
         # Trying to get the date from GitHub
         date_value = get_rule_age_github(owner, repo, branch, file_path)
         # Add the date to the cache
         date_lookup_cache[file_path] = date_value
      # Add the date to the rule meta data
      rule_meta_data.append({'date': date_value})
   return rule_meta_data


# Get the age of the YARA rule file from GitHub
def get_rule_age_github(owner, repo, branch, file_path):
   try:
      url = f"https://api.github.com/repos/{owner}/{repo}/commits?path={file_path}&sha={branch}"
      response = requests.get(url)
      commits = response.json()

      if commits:
         last_commit = commits[0]
         last_modified_date_string = last_commit['commit']['committer']['date']
         last_modified_date = dateparser.parse(last_modified_date_string).strftime("%Y-%m-%d")
         print(f"The file was last modified on: {last_modified_date}")
      else:
         print("File has not been modified or does not exist.")
   except Exception as e:
      print(e)
      print("Could not get the last modified date from GitHub.")
      last_modified_date = "N/A"

   return last_modified_date
