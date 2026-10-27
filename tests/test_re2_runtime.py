"""Verify the RE2 API used by the pinned QA submodule."""
import unittest

import re2

from qa.yaraQA.main.performance_timer import PerformanceTimer, findall_compat


class TestRe2Runtime(unittest.TestCase):
    def test_qa_match_iteration_supports_offsets_and_groups(self):
        pattern = re2.compile(r'[a-z]')
        self.assertEqual(findall_compat(pattern, 'abc'), ['a', 'b', 'c'])
        self.assertEqual(pattern.match(' abc', 1).group(0), 'a')

    def test_qa_timer_accepts_re2_patterns(self):
        timer = PerformanceTimer.__new__(PerformanceTimer)
        timer.test_string = 'sample text'
        self.assertGreater(timer.test_regex_performance('/sample/', iterations=1), 0)
