#!/usr/bin/env python3
"""Derive portable CSV tables from included JSON. No scientific recomputation."""
import csv,json,statistics
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; R=ROOT/'results'
def write(name,rows):
    with (R/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
parts=['structured','grid','cycle','format','graph-free','graph-nm','random-0','random-1','random-2']
write('summary.csv',[{k:v for k,v in json.loads((R/(p+'.json')).read_text()).items() if k!='rows'} for p in parts])
rows=[]
for p in ['equal-small','equal-large']:rows+=json.loads((R/(p+'.json')).read_text())['rows']
agg=[]
for g in sorted({r['groups'] for r in rows}):
    rr=[r for r in rows if r['groups']==g]
    agg.append(dict(groups=g,guards=rr[0]['guards'],terms=rr[0]['terms'],legal_masks=rr[0]['legal_masks'],status=rr[0]['status'],median_seconds=statistics.median(r['wall_seconds'] for r in rr),min_seconds=min(r['wall_seconds'] for r in rr),max_seconds=max(r['wall_seconds'] for r in rr),count_operation_charge=rr[0]['count_operation_charge']))
write('equality.csv',agg)
# Plot view: only completed exact-equality runs.  The unresolved 256-group
# preflight is retained in equality.csv but is not a timing measurement.
write('equality-plot.csv',[r for r in agg if r['status']=='equal'])
for part in ['orders','cliques']:
    rr=json.loads((R/(part+'.json')).read_text())['rows']
    keys=list(dict.fromkeys(k for r in rr for k in r if k!='guard_order'))
    write(part+'.csv',[{k:r.get(k,'') for k in keys} for r in rr])
rr=json.loads((R/'reduction.json').read_text())['rows']
write('reduction.csv',rr)
rr=json.loads((R/'certificates.json').read_text())['rows']
write('certificates.csv',rr)
