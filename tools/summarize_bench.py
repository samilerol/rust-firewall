"""Summarize raw benchmark CSV using stdlib only; exclude warmup sample zero."""
import csv
import math
import statistics
import sys
from collections import defaultdict

cases = defaultdict(list)
with open(sys.argv[1], newline='', encoding='utf-8') as source:
    for row in csv.DictReader(source):
        sample = int(row['sample'])
        operations = int(row['operations'])
        elapsed = int(row['elapsed_ns'])
        if sample < 0 or operations <= 0 or elapsed < 0:
            raise ValueError('Invalid timing record')
        if sample:
            cases[row['case']].append(elapsed / operations)
if not cases:
    raise ValueError('No measured samples')
print('Sample 0 (warmup) excluded. Times include loop/harness overhead. No regression threshold.\n')
print('| Case | Samples | Median ns/op | Min ns/op | Max ns/op |')
print('|---|---:|---:|---:|---:|')
for case, values in cases.items():
    assert all(math.isfinite(value) for value in values)
    print(f'| {case} | {len(values)} | {statistics.median(values):.3f} | {min(values):.3f} | {max(values):.3f} |')
