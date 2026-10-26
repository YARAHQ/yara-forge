"""Merged files must retain the matching semantics of their own global gates."""
import datetime
import os
import unittest
from unittest.mock import patch

from plyara import Plyara
import yara

from main.rule_processors import date_lookup_cache, process_yara_rules
from qa.rule_qa import check_issues_critical, evaluate_rules_quality
import test_rule_output_guardrails as guardrails


class TestGlobalRuleScope(unittest.TestCase):
    def render(self, files):
        repo = guardrails.build_repo_payload([])[0]
        repo['rules_sets'] = []
        for path, source in files.items():
            repo['rules_sets'].append({'file_path': path, 'rules': Plyara().parse_string(source)})
            date_lookup_cache[os.path.join(repo['repo_path'], path)] = (
                datetime.datetime(2024, 1, 1), datetime.datetime(2024, 1, 2))
        process_yara_rules([repo], dict(guardrails.TEST_CONFIG, meta_data_order=[]))
        rules = [rule for group in repo['rules_sets'] for rule in group['rules']]
        self.processed_repo = repo
        for rule in rules:
            self.assertEqual(check_issues_critical(rule), [])
        output = guardrails.TestRuleOutputGuardrails()._render_package(rules)
        return yara.compile(source=output)

    def test_global_gate_cannot_suppress_unrelated_file(self):
        compiled = self.render({
            'gated.yar': 'global rule GATE { condition: false } rule PAYLOAD { condition: true }',
            'other.yar': 'rule OTHER { condition: filesize >= 0 }',
        })
        self.assertEqual([m.rule for m in compiled.match(data=b'x')], ['SAMPLEREPO_OTHER'])

    def test_private_global_gate_is_not_dropped(self):
        compiled = self.render({'gated.yar': '''
            private global rule GATE { condition: filesize < 2 }
            rule PAYLOAD { condition: filesize > 0 }
        '''})
        self.assertEqual([m.rule for m in compiled.match(data=b'x')], ['SAMPLEREPO_PAYLOAD'])
        self.assertEqual(compiled.match(data=b'long'), [])

    def test_multiple_gates_and_public_dependencies_keep_original_semantics(self):
        source = '''
            rule HELPER { condition: filesize > 0 }
            global rule GATE { condition: HELPER }
            private global rule SIZE { condition: filesize < 5 }
            rule PAYLOAD { strings: $a = "yes" condition: $a }
        '''
        original = yara.compile(source=source)
        compiled = self.render({'gated.yar': source})
        for data in (b'', b'x', b'yes', b'yes indeed'):
            with self.subTest(data=data):
                expected = {'SAMPLEREPO_' + m.rule for m in original.match(data=data)}
                self.assertEqual({m.rule for m in compiled.match(data=data)}, expected)

        payload = next(m for m in compiled.match(data=b'yes') if m.rule == 'SAMPLEREPO_PAYLOAD')
        self.assertEqual(payload.strings[0].identifier, '$a')
        self.assertEqual(payload.strings[0].instances[0].offset, 0)
        self.assertEqual(payload.strings[0].instances[0].matched_data, b'yes')

    def test_filtered_global_rule_still_gates_remaining_rules(self):
        compiled = self.render({'gated.yar': '''
            global rule GATE { meta: importance = -10 condition: filesize < 2 }
            rule PAYLOAD { condition: filesize > 0 }
        '''})
        self.assertEqual([m.rule for m in compiled.match(data=b'x')], ['SAMPLEREPO_PAYLOAD'])
        self.assertEqual(compiled.match(data=b'long'), [])

    def test_public_wrapper_is_scored_using_its_original_strings(self):
        self.render({'gated.yar': '''
            private global rule GATE { condition: filesize > 0 }
            rule PAYLOAD { strings: $a = "yes" condition: $a }
        '''})
        with patch('qa.rule_qa.ForgeYaraQA') as qa, \
                patch('qa.rule_qa.retrieve_custom_quality_reduction', return_value=0), \
                patch('qa.rule_qa.retrieve_custom_score', return_value=None), \
                patch('qa.rule_qa.write_issues_to_file'):
            qa.return_value.analyze_rule.return_value = []
            evaluate_rules_quality([self.processed_repo], {'issue_levels': {}})
            analyzed = [call.args[0] for call in qa.return_value.analyze_rule.call_args_list]
            public = next(rule for rule in analyzed if rule['rule_name'] == 'SAMPLEREPO_PAYLOAD')
            self.assertEqual(public['strings'][0]['value'], 'yes')
