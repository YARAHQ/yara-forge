"""Keep file-local global constraints when combining independent YARA sources."""
from copy import deepcopy
import hashlib


def isolate_global_rules(rule_set):
    """Represent original predicates privately and gate their public matches.

    Simply attaching the gates to existing public conditions can introduce
    cycles when a global rule references a public rule. Private predicates
    preserve the original dependency graph; public wrappers apply every gate.
    """
    rules = rule_set['rules']
    globals_ = [rule for rule in rules if 'global' in rule.get('scopes', [])]
    if not globals_:
        return

    prefix = hashlib.sha256(rule_set['file_path'].encode('utf-8')).hexdigest()[:16]
    names = {rule['rule_name'] for rule in rules}
    predicate_names = {}
    for index, rule in enumerate(rules):
        name = f'__forge_scope_{prefix}_{index}'
        while name in names:
            name += '_'
        names.add(name)
        predicate_names[rule['rule_name']] = name

    gates = [predicate_names[rule['rule_name']] for rule in globals_]
    predicates = []
    wrappers = []
    for rule in rules:
        predicate = deepcopy(rule)
        predicate['rule_name'] = predicate_names[rule['rule_name']]
        predicate['scopes'] = ['private']
        predicate['condition_terms'] = [predicate_names.get(term, term)
                                        for term in rule['condition_terms']]
        predicates.append(predicate)
        if 'private' in rule.get('scopes', []):
            continue

        wrapper = deepcopy(rule)
        wrapper['scopes'] = []
        wrapper.pop('strings', None)
        wrapper.pop('raw_strings', None)
        required = list(dict.fromkeys([predicate['rule_name']] + gates))
        wrapper['condition_terms'] = []
        for name in required:
            if wrapper['condition_terms']:
                wrapper['condition_terms'].append('and')
            wrapper['condition_terms'].append(name)
        wrapper['raw_condition'] = 'condition: ' + ' '.join(wrapper['condition_terms'])
        # Efficiency checks must still inspect the original strings and logic.
        wrapper['qa_rule'] = predicate
        wrappers.append(wrapper)

    rule_set['rules'] = predicates + wrappers
