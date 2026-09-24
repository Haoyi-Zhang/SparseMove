#!/usr/bin/env python3
"""Exhaustively validate the fixed-zero Max-Cut reduction on bounded graphs.

The compact JSONL input identifies every graph by its lexicographic edge-bit code,
its support promise, and its Max-Cut threshold.  The script reconstructs the full
mapping pair and compares literal byte traffic with the closed-form gadget value.
"""
from __future__ import annotations
import argparse,itertools,json,os,resource,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from dataflow.generate import cut_threshold
from dataflow.literal import masks,traffic
from dataflow.model import difference,eval_difference


def families():
    # Every simple graph through four vertices under independent supports.
    for promise,max_vertices in [('free',4),('nm',3)]:
        for n in range(2,max_vertices+1):
            possible=list(itertools.combinations(range(n),2))
            for code in range(1,1<<len(possible)):
                edges=[e for i,e in enumerate(possible) if code>>i&1]
                for threshold in range(1,len(edges)+1):
                    yield promise,n,code,edges,threshold


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,default=ROOT/'results')
    ap.add_argument('--inputs',type=Path,default=ROOT/'inputs')
    args=ap.parse_args()
    if hasattr(os,'sched_getaffinity'):
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(42,44))
    args.out.mkdir(parents=True,exist_ok=True);args.inputs.mkdir(parents=True,exist_ok=True)
    start=time.monotonic();cpu=time.process_time();stats={};pairs=mask_count=truth=0;max_events=0
    with (args.inputs/'reduction.jsonl').open('w') as fi:
        for promise,n,code,edges,threshold in families():
            fi.write(json.dumps({'promise':promise,'vertices':n,'graph_code':code,
                                 'threshold':threshold},separators=(',',':'))+'\n')
            p=cut_threshold(n,edges,threshold,promise);c,terms=difference(p)
            observed=[]
            for x in masks(p['kernel']):
                cut=sum((((x>>(4*u if promise=='nm' else u))&1)^
                         ((x>>(4*v if promise=='nm' else v))&1)) for u,v in edges)
                expected=4*(cut-(threshold-1))
                literal=traffic(p,'target',x)[0]-traffic(p,'source',x)[0]
                symbolic=eval_difference(c,terms,x)
                if literal!=expected or symbolic!=expected:
                    raise AssertionError((promise,n,code,threshold,x,literal,symbolic,expected))
                observed.append(literal)
            maxcut=max(sum(((x>>u)^(x>>v))&1 for u,v in edges)
                       for x in range(1<<n))
            expected_max=4*(maxcut-(threshold-1))
            if max(observed)!=expected_max or (all(z<=0 for z in observed)!=(maxcut<threshold)):
                raise AssertionError((promise,n,code,threshold,'universal'))
            if p['architecture']['capacity']!=[8]:
                raise AssertionError((promise,n,code,threshold,'capacity'))
            key=(promise,n);r=stats.setdefault(key,{'promise':promise,'vertices':n,
                'pair_count':0,'mask_count':0,'zero_bound_true':0,'zero_bound_false':0})
            r['pair_count']+=1;r['mask_count']+=len(observed)
            r['zero_bound_true']+=maxcut<threshold;r['zero_bound_false']+=maxcut>=threshold
            pairs+=1;mask_count+=len(observed);truth+=maxcut<threshold
            max_events=max(max_events,len(p['kernel']['events']))
    use=resource.getrusage(resource.RUSAGE_SELF)
    result={'part':'reduction','pair_count':pairs,'mask_count':mask_count,
            'zero_bound_true':truth,'zero_bound_false':pairs-truth,
            'max_events':max_events,'capacity_bytes':8,
            'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.monotonic()-start,
            'peak_rss_kib':use.ru_maxrss,'swap_events':use.ru_nswap,'workers':1,
            'rows':[stats[k] for k in sorted(stats)]}
    (args.out/'reduction.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))

if __name__=='__main__':main()
