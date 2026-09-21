#!/usr/bin/env python3
"""Convert automatic Mihomo groups to fixed select groups safely.

The source configuration is never overwritten. Runtime selections are read
from a loopback controller and preserved when the selected member still
exists in the incoming configuration.
"""
import argparse
import copy
import json
import os
import sys

import mihomo_policy as policy

AUTO_TYPES = {'url-test', 'fallback', 'load-balance'}
AUTO_KEYS = {'url', 'interval', 'timeout', 'lazy', 'tolerance',
             'max-failed-times', 'expected-status', 'strategy'}


def selections(config):
    live = policy.api(config, '/proxies')['proxies']
    result = {}
    for group in config.get('proxy-groups', []):
        name = group.get('name')
        actual = live.get(name, {})
        selected = actual.get('now')
        members = group.get('proxies', [])
        if selected and selected in members:
            result[name] = selected
    return result


def manualize(text, selected):
    source = policy.parse(text)
    updated = copy.deepcopy(source)
    groups = updated.get('proxy-groups')
    if not isinstance(groups, list):
        raise policy.PolicyError('proxy-groups must be a list')
    for group in groups:
        if group.get('type') not in AUTO_TYPES:
            continue
        members = group.get('proxies', [])
        if not isinstance(members, list) or not members:
            raise policy.PolicyError('automatic group has no static members: ' + str(group.get('name')))
        current = selected.get(group.get('name'))
        if current and current not in members:
            raise policy.PolicyError('selected member disappeared: ' + str(group.get('name')))
        if current:
            members = [current] + [member for member in members if member != current]
        group['proxies'] = members
        group['type'] = 'select'
        for key in AUTO_KEYS:
            group.pop(key, None)
    profile = updated.get('profile', {})
    if not isinstance(profile, dict):
        raise policy.PolicyError('profile must be a mapping')
    profile['store-selected'] = True
    updated['profile'] = profile
    if set(source) != set(updated) or any(source.get(key) != updated.get(key)
                                          for key in set(source) - {'proxy-groups', 'profile'}):
        raise policy.PolicyError('manualization changed a protected top-level section')
    result = policy.replace_sections(text, {'proxy-groups': updated['proxy-groups'],
                                            'profile': updated['profile']})
    if policy.parse(result) != updated:
        raise policy.PolicyError('manualization semantic verification failed')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--runtime-config', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source = policy.read(args.source)
    runtime = policy.parse(policy.read(args.runtime_config))
    result = manualize(source, selections(runtime))
    with open(args.output, 'w', encoding='utf-8') as stream:
        stream.write(result)
    os.chmod(args.output, 0o600)
    print(json.dumps({'manualized': True, 'groups': sum(
        1 for group in policy.parse(result).get('proxy-groups', [])
        if group.get('type') == 'select')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (policy.PolicyError, OSError, KeyError, TypeError, ValueError):
        error = sys.exc_info()[1]
        print('manualization rejected: ' + (str(error) if isinstance(error, policy.PolicyError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
