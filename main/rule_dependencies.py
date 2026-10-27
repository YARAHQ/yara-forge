"""Resolve rule dependencies in the order required by the YARA compiler."""


def get_rule_dependencies(rule):
    """Return each transitive dependency once, before its dependents.

    Older callers may still supply only ``private_rules_used`` mappings.
    """
    dependencies = []
    visited = set()
    visiting = {rule['rule_name']}

    def visit(current):
        name = current['rule_name']
        if name in visiting:
            raise ValueError(f"Circular rule dependency: {name}")
        if name in visited:
            return
        visiting.add(name)
        for mapping in current.get('rule_dependencies', current.get('private_rules_used', [])):
            visit(mapping['rule'])
        visiting.remove(name)
        visited.add(name)
        dependencies.append(current)

    for mapping in rule.get('rule_dependencies', rule.get('private_rules_used', [])):
        visit(mapping['rule'])
    return dependencies
