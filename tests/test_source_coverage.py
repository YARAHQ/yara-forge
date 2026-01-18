"""
Test source repo coverage in full package.
"""
import unittest
import subprocess
import os
import tempfile
import yaml
import re
import shutil
from pathlib import Path

class TestSourceCoverage(unittest.TestCase):
    """
    Test that full package covers all source repos.
    """
    def test_full_package_covers_all_repos(self):
        """
        Run pipeline, check build_stats.md full table: all repos total_rules >0.
        """
        config_path = str(Path(__file__).parent.parent / 'yara-forge-config.yml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Subset stable repos for test speed
        subset_repos = [r for r in config['yara_repositories'] 
                        if r['name'] in ['R3c0nst', 'DeadBits']]
        config['yara_repositories'] = subset_repos
        expected_repos = {r['name'] for r in subset_repos}
        
        with tempfile.TemporaryDirectory() as tmp_base:
            tmp_repos_dir = os.path.join(tmp_base, 'repos')
            tmp_config_path = os.path.join(tmp_base, 'temp-config.yml')
            
            # Write temp config
            with open(tmp_config_path, 'w') as f:
                yaml.dump(config, f)
            
            shutil.copy(Path(__file__).parent.parent / 'yara-forge-custom-scoring.yml', tmp_base)
            
            # Run yara-forge.py
            cmd = ['python', str(Path(__file__).parent.parent / 'yara-forge.py'), '-c', 'temp-config.yml']
            result = subprocess.run(cmd, cwd=tmp_base, 
                                  capture_output=True, text=True, timeout=900)
            self.assertEqual(result.returncode, 0, f"Pipeline failed: {result.stderr}")
            
            # Check build_stats.md
            build_stats_path = os.path.join(tmp_base, 'build_stats.md')
            self.assertTrue(os.path.exists(build_stats_path), "No build_stats.md")
            
            stats = self._parse_build_stats_full(build_stats_path)
            self.assertEqual(set(stats.keys()), expected_repos,
                           f"Missing repos: {expected_repos - set(stats)}")
            for repo, count in stats.items():
                self.assertGreater(count, 0, f"Repo '{repo}' has 0 rules in full")
    
    def _parse_build_stats_full(self, path):
        """
        Parse build_stats.md ## full table: repo -> total_rules.
        """
        with open(path, 'r') as f:
            content = f.read()
        
        # Find full section
        match = re.search(r'## full\n\n\| Repo \| Total Rules \| .*?\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
        if not match:
            self.fail("No '## full' section in build_stats.md")
        
        table = match.group(1)
        rows = re.findall(r'^\| ([^|]+) \| (\d+) \|', table, re.MULTILINE)
        return {repo.strip(): int(count) for repo, count in rows}


if __name__ == '__main__':
    unittest.main()
