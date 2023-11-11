"""
Test the rule collector.
"""
import unittest
from main.rule_collector import retrieve_yara_rule_sets

class TestRuleCollector(unittest.TestCase):
    """
    Test the rule collector.
    """
    def test_retrieve_yara_rule_sets(self):
        """
        Test the retrieve_yara_rule_sets function.
        """
        # Mock the inputs
        repo_staging_dir = './repos'
        yara_repos = [{'name': 'test', 'author': 'test', 'url': 'https://github.com/Neo23x0/YARA-Style-Guide', 'branch': 'master', 'quality': 90}]
        
        # Call the function
        result = retrieve_yara_rule_sets(repo_staging_dir, yara_repos)
        
        # Check the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'test')
        self.assertEqual(len(result[0]['rules_sets']), 6)
        self.assertEqual(len(result[0]['rules_sets'][0]['rules']), 2)

if __name__ == '__main__':
    unittest.main()
