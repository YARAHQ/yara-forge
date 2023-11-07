import sys
import plyara
import traceback

def readFiles(input_files):
   """
   Reads the YARA input files
   :return:
   """
   rule_sets = []
   # Loop over input files
   for f in input_files:
      try:
         p = plyara.Plyara()
         file_data = ""
         # Read file
         with open(f, 'r') as fh:
            file_data = fh.read()
         # Skip files without rule
         if 'rule' not in file_data:
            continue
         rule_set = p.parse_string(file_data)
         rule_sets.append(rule_set)
      except Exception as e:
            print("Error parsing YARA rule file '%s'" % f)
            traceback.print_exc()
            sys.exit(1)
   # Return the parsed rules
   return rule_sets