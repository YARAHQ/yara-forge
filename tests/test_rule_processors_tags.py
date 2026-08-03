"""
Tests for tag generation in rule processing.
"""
import unittest

from main.rule_processors import add_tags_to_rule


def build_rule(meta_key, meta_value):
    """
    Build the minimal rule structure add_tags_to_rule works on.
    """
    return {
        'rule_name': 'TestRule',
        'metadata': [{meta_key: meta_value}],
        'raw_condition': 'condition:\n\t\ttrue\n',
    }


class TestAddTagsToRule(unittest.TestCase):
    """
    Test that every meta key listed in tag_names turns its value into a tag.
    """

    def test_attack_technique_keys_become_tags(self):
        """
        The singular 'attack_technique' and the plural 'mitre_attack_techniques'
        are listed as tag sources and have to be picked up like their siblings.
        """
        cases = {
            'attack_technique': 'T1055',
            'attack_techniques': 'T1056',
            'mitre_attack_techniques': 'T1057',
            'mitre_attack_technique': 'T1058',
        }

        for meta_key, meta_value in cases.items():
            with self.subTest(meta_key=meta_key):
                rule = add_tags_to_rule(build_rule(meta_key, meta_value))
                self.assertIn(meta_value, rule['tags'])


if __name__ == '__main__':
    unittest.main()
