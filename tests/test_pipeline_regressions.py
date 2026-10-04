"""Offline regressions for collection, normalization, QA, and packaging."""
import datetime
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, patch

from git import Actor, Repo
from plyara import Plyara
from plyara.utils import rebuild_yara_rule
import yara

from main.other_evals import PerformanceTimer
from main.rule_collector import retrieve_yara_rule_sets
from main.rule_dependencies import get_rule_dependencies
from main.rule_processors import date_lookup_cache, process_yara_rules
from qa.rule_qa import (ForgeYaraQA, check_issues_critical,
                        check_syntax_issues, evaluate_rules_quality)
import test_rule_output_guardrails as guardrails

TEST_CONFIG = guardrails.TEST_CONFIG
build_repo_payload = guardrails.build_repo_payload


class TestPipelineRegressions(unittest.TestCase):
    def process(self, files):
        repo = build_repo_payload([])[0]
        repo['rules_sets'] = []
        date_lookup_cache.clear()
        for filename, text in files.items():
            repo['rules_sets'].append({'file_path': filename,
                                      'rules': Plyara().parse_string(text)})
            date_lookup_cache[os.path.join(repo['repo_path'], filename)] = (
                datetime.datetime(2024, 1, 1), datetime.datetime(2024, 1, 2))
        config = dict(TEST_CONFIG, meta_data_order=[])
        return process_yara_rules([repo], config)[0]

    def render(self, rules):
        case = guardrails.TestRuleOutputGuardrails()
        output = case._render_package(rules)
        yara.compile(source=output)
        return output

    def test_three_distinct_rules_with_the_same_name_survive(self):
        repo = self.process({
            'one.yar': 'rule Foo { condition: true }',
            'two.yar': 'rule Foo { condition: false }',
            'three.yar': 'rule Foo { condition: filesize > 0 }',
            'four.yar': 'rule Foo_1 { condition: filesize > 1 }',
        })
        rules = [rule for group in repo['rules_sets'] for rule in group['rules']]
        self.assertEqual(len(rules), 4)
        self.assertEqual(len({rule['rule_name'] for rule in rules}), 4)
        self.render(rules)

    def test_public_references_and_dependencies_are_preserved(self):
        repo = self.process({'rules.yar': '''
            rule Helper { condition: true }
            rule Main { condition: Helper and filesize > 0 }
        '''})
        helper, main = repo['rules_sets'][0]['rules']
        self.assertIn(helper['rule_name'], main['condition_terms'])
        self.assertEqual(check_issues_critical(main), [])
        self.assertEqual(check_syntax_issues(main), [])
        # The helper is needed even if it would fail the package's score filter.
        helper['metadata'].append({'importance': -10})
        output = self.render([main, helper])
        self.assertEqual(output.count('rule ' + helper['rule_name'] + '\n'), 1)
        self.assertLess(output.index('rule ' + helper['rule_name']),
                        output.index('rule ' + main['rule_name']))

    def test_nested_private_dependencies_compile_in_qa_and_output(self):
        repo = self.process({'rules.yar': '''
            private rule A { condition: filesize > 0 }
            private rule B { condition: A and filesize < 100 }
            rule Main { condition: B }
            rule Other { condition: B and filesize < 50 }
        '''})
        a, b, main, other = repo['rules_sets'][0]['rules']
        self.assertEqual(get_rule_dependencies(main), [a, b])
        self.assertEqual(check_issues_critical(main), [])
        self.assertEqual(check_syntax_issues(main), [])
        output = self.render([main, other])
        for dependency in (a, b):
            declarations = re.findall(r'\brule\s+' + re.escape(dependency['rule_name']) + r'\b', output)
            self.assertEqual(len(declarations), 1)
        self.assertLess(output.index('rule ' + a['rule_name']),
                        output.index('rule ' + b['rule_name']))
        self.assertLess(output.index('rule ' + b['rule_name']),
                        output.index('rule ' + main['rule_name']))

    def test_same_helper_name_in_different_files_keeps_its_binding(self):
        repo = self.process({
            'one.yar': 'private rule Helper { condition: true } rule One { condition: Helper }',
            'two.yar': 'private rule Helper { condition: false } rule Two { condition: Helper }',
        })
        first, second = repo['rules_sets']
        self.assertIn(first['rules'][0]['rule_name'], first['rules'][1]['condition_terms'])
        self.assertIn(second['rules'][0]['rule_name'], second['rules'][1]['condition_terms'])
        self.assertNotEqual(first['rules'][0]['rule_name'], second['rules'][0]['rule_name'])
        output = self.render([first['rules'][1], second['rules'][1]])
        self.assertEqual([match.rule for match in yara.compile(source=output).match(data=b'x')],
                         [first['rules'][1]['rule_name']])

    def test_referenced_public_duplicate_is_not_removed(self):
        repo = self.process({'rules.yar': '''
            rule Earlier { condition: true }
            rule Helper { condition: true }
            rule Main { condition: Helper }
        '''})
        rules = repo['rules_sets'][0]['rules']
        self.assertEqual(len(rules), 3)
        self.assertEqual(check_issues_critical(rules[-1]), [])
        self.render(rules)

    def test_numeric_and_boolean_metadata_produce_valid_tags(self):
        repo = self.process({'rules.yar': '''
            rule Numeric {
                meta:
                    category = 1
                    type = true
                    mitre_attack_techniques = "T1059, T1071"
                condition: true
            }
        '''})
        rule = repo['rules_sets'][0]['rules'][0]
        self.assertIn('_1', rule['tags'])
        self.assertIn('TRUE', rule['tags'])
        self.assertIn('T1059', rule['tags'])
        yara.compile(source=rebuild_yara_rule(rule))

    def test_dependency_cycles_are_reported_as_critical(self):
        rule = Plyara().parse_string('rule Loop { condition: true }')[0]
        rule['rule_dependencies'] = [{'rule': rule}]
        issues = check_issues_critical(rule)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['level'], 4)

    def test_live_performance_issue_is_penalized_once(self):
        repo = self.process({'rules.yar': 'rule Sample { condition: true }'})
        issue = {'rule': repo['rules_sets'][0]['rules'][0]['rule_name'],
                 'id': 'PI1', 'type': 'performance', 'level': 2}
        config = dict(TEST_CONFIG, issue_levels={1: -2, 2: -25, 3: -70, 4: -1000})
        with patch('qa.rule_qa.ForgeYaraQA') as qa_class, \
                patch('qa.rule_qa.check_issues_critical', return_value=[]), \
                patch('qa.rule_qa.check_syntax_issues', return_value=[]), \
                patch('qa.rule_qa.retrieve_custom_quality_reduction', return_value=0), \
                patch('qa.rule_qa.retrieve_custom_score', return_value=None), \
                patch('qa.rule_qa.write_issues_to_file'):
            qa_class.return_value.analyze_rule.return_value = [issue]
            qa_class.return_value.analyze_live_rule_performance.return_value = [issue.copy()]
            result = evaluate_rules_quality([repo], config)
            metadata = result[0]['rules_sets'][0]['rules'][0]['metadata']
            self.assertEqual(next(item['quality'] for item in metadata if 'quality' in item), 55)
            qa_class.return_value.analyze_live_rule_performance.assert_not_called()

    def test_forge_qa_uses_full_sample_regex_search(self):
        with patch.object(PerformanceTimer, '__init__', return_value=None):
            qa = ForgeYaraQA()
        timer = qa.performance_timer
        timer.test_string = 'prefix needle middle needle suffix'
        pattern = re.compile('needle')
        spy = Mock(wraps=pattern)
        with patch('main.other_evals.re.compile', return_value=spy):
            timer.test_regex_performance('/needle/', iterations=2)
        self.assertEqual(spy.findall.call_count, 2)
        spy.findall.assert_called_with(timer.test_string)
        self.assertEqual(pattern.findall(timer.test_string), ['needle', 'needle'])


class TestSharedRepositoryCollection(unittest.TestCase):
    def collect(self, root_source=False):
        with tempfile.TemporaryDirectory() as tmp:
            remote = Path(tmp) / 'source'
            remote.mkdir()
            source = Repo.init(remote)
            for directory in ('Source One', 'SourceTwo'):
                path = remote / directory
                path.mkdir()
                (path / 'rule.yar').write_text('rule Sample { condition: true }')
            (remote / 'LICENSE').write_text('Test license')
            source.index.add(['Source One/rule.yar', 'SourceTwo/rule.yar', 'LICENSE'])
            identity = Actor('Test', 'test@example.invalid')
            source.index.commit('Fixture', author=identity, committer=identity)
            sources = [{'name': directory, 'url': 'https://example.invalid/owner/shared',
                        'author': 'Test', 'quality': 80, 'branch': source.active_branch.name,
                        'path': directory} for directory in ('Source One', 'SourceTwo')]
            if root_source:
                sources[1].pop('path')
            clone = Repo.clone_from
            with patch('main.rule_collector.Repo.clone_from',
                       side_effect=lambda url, destination, **kw: clone(str(remote), destination, **kw)) as mock:
                results = retrieve_yara_rule_sets(str(Path(tmp) / 'staging'), sources)
            self.assertEqual(mock.call_count, 1)
            counts = [sum(len(group['rules']) for group in result['rules_sets'])
                      for result in results]
            self.assertEqual(counts, [1, 2] if root_source else [1, 1])
            self.assertEqual(results[0]['commit_hash'], results[1]['commit_hash'])

    def test_shared_sparse_paths_are_all_checked_out(self):
        self.collect()

    def test_root_source_disables_sparse_checkout(self):
        self.collect(root_source=True)
