import plyara
import requests


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
   # Look for the reference in the rule meta data
   reference_found = False
   for meta_data in rule_meta_data:
      if 'reference' in meta_data:
         reference_found = True
   if not reference_found:
      rule_meta_data.append({'reference': rule_set_url})
   return rule_meta_data


# Modify the YARA rule date
def process_yara_rule_date(rule_meta_data):
   for metadata in rule_meta_data:
      if not 'date' in metadata:
         metadata['date'] = "2021-01-01"
   return rule_meta_data


# Get the age of the YARA rule file from GitHub
def get_rule_age_github(url, file_path):
   url = f"{url}/commits?path={file_path}" 
   response = requests.get(url)
   commits = response.json()

   if commits:
      last_commit = commits[0]
      last_modified_date = last_commit['commit']['committer']['date']
      print(f"The file was last modified on: {last_modified_date}")
   else:
      print("File has not been modified or does not exist.")

   return last_modified_date