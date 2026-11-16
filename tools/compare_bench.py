"""Compare identical benchmark cases on one runner; observations, not speed guarantees."""
import csv
import statistics
import sys
from collections import defaultdict

def medians(path):
    values = defaultdict(list)
    with open(path, newline='', encoding='utf-8') as source:
        for row in csv.DictReader(source):
            if int(row['sample']) > 0:
                operations = int(row['operations'])
                elapsed = int(row['elapsed_ns'])
                if operations <= 0 or elapsed < 0:
                    raise ValueError('Invalid timing record')
                values[row['case']].append(elapsed / operations)
    if not values:
        raise ValueError('Missing measured samples')
    return {name: statistics.median(samples) for name, samples in values.items()}

baseline, current = map(medians, sys.argv[1:3])
common = baseline.keys() & current.keys()
if not common:
    raise ValueError('No comparable cases')
print('Same-runner, same toolchain; warmup excluded. Current ran before baseline. Shared-runner noise, hashing and order effects are uncontrolled. No regression threshold.\n')
print('| Case | Baseline median ns/op | Current median ns/op | Baseline / current |')
print('|---|---:|---:|---:|')
for name in sorted(common):
    ratio = f'{baseline[name] / current[name]:.2f}' if current[name] > 0 else 'n/a'
    print(f'| {name} | {baseline[name]:.3f} | {current[name]:.3f} | {ratio} |')
