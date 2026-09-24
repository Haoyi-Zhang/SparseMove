#!/usr/bin/env python3
"""Fixed-budget equality, ordering and cut-bound experiments."""
from __future__ import annotations
import argparse,itertools,json,os,random,resource,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dataflow.generate import structured,cut_graph
from dataflow.model import difference
from dataflow.moment import Counter,Budget,AnalysisLimit
from dataflow.checker import check_equal,check_upper
from dataflow.producer import prove_upper


def require(condition: bool, context) -> None:
    if not condition:
        raise RuntimeError(repr(context))


def main():
    ap=argparse.ArgumentParser();ap.add_argument('part',choices=['equal-small','equal-large','orders','cliques']);ap.add_argument('--out',type=Path,default=ROOT/'results');args=ap.parse_args()
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3));resource.setrlimit(resource.RLIMIT_CPU,(42,44))
    rows=[];start=time.monotonic();cpu=time.process_time();args.out.mkdir(parents=True,exist_ok=True)
    if args.part.startswith('equal'):
        for groups in ([1,2,4,8,16,32] if args.part=='equal-small' else [64,128,256]):
            p=structured(groups);c,terms=difference(p);ctr=Counter(p['kernel'])
            for repeat in range(1 if groups==256 else 3):
                t=time.monotonic();cput=time.process_time();budget=Budget(seconds=30)
                row={'groups':groups,'guards':p['kernel']['guards'],'terms':len(terms),'legal_masks':ctr.avoid(0),'repeat':repeat}
                try:
                    q = ctr.square(c, terms, budget=budget)
                    require(q == 0, ('nonzero structured square', groups, repeat, q))
                    row.update(status='equal',square_sum=q)
                except AnalysisLimit as e:row.update(status='unresolved',reason=str(e))
                row.update(cpu_seconds=time.process_time()-cput,wall_seconds=time.monotonic()-t,count_operation_charge=budget.used)
                rows.append(row)
    elif args.part=='orders':
        for groups in [4,8,12,16]:
            p=structured(groups);n=p['kernel']['guards']
            orders={'grouped':list(range(n)), 'interleaved':[4*j+k for k in range(4) for j in range(groups)]}
            shuffled=list(range(n));random.Random(9173+groups).shuffle(shuffled);orders['shuffled']=shuffled
            for label,order in orders.items():
                t=time.monotonic();cput=time.process_time();row={'groups':groups,'guards':n,'order':label,'guard_order':order,'max_layer':8192,'max_total':50000,'time_cap_seconds':5}
                try:
                    proof=prove_upper(p,order=order,max_layer=8192,max_total=50000,seconds=5)
                    cr=check_upper(p,proof,0,proof['bound'],max_layer=8192,max_total=50000,seconds=5)
                    require(proof['bound'] == 0 and cr['exact'], ('invalid order certificate', groups, label))
                    row.update(status='certified', bound=0, **proof['statistics'])
                except AnalysisLimit as e:row.update(status='unresolved',reason=str(e))
                row.update(cpu_seconds=time.process_time()-cput,wall_seconds=time.monotonic()-t);rows.append(row)
    else:
        for n in range(3,13):
            edges=list(itertools.combinations(range(n),2));p=cut_graph(n,edges)
            t=time.monotonic();cput=time.process_time();proof=prove_upper(p);cr=check_upper(p,proof,0,proof['bound'])
            require(proof['bound'] == 4 * (n * n // 4) and cr['exact'], ('invalid clique certificate', n))
            rows.append({'vertices':n,'edges':len(edges),'joint_bound':proof['bound'],'sum_local_bounds':4*len(edges),
                         **proof['statistics'],'cpu_seconds':time.process_time()-cput,'wall_seconds':time.monotonic()-t,'status':'certified'})
    use=resource.getrusage(resource.RUSAGE_SELF)
    result={'part':args.part,'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.monotonic()-start,
            'peak_rss_kib':use.ru_maxrss,'swap_events':use.ru_nswap,'workers':1,'rows':rows}
    (args.out/f'{args.part}.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'}));print(json.dumps(rows))

if __name__=='__main__':main()
