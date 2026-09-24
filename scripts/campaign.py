#!/usr/bin/env python3
"""Bounded deterministic scientific campaign; no third-party dependencies.

A part is a resumable unit, not a parallel worker. Generated inputs are exact
scientific inputs. Verification results are recomputed, not imported as answers.
"""
from __future__ import annotations
import argparse,csv,itertools,json,os,random,resource,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from dataflow import generate as gen
from dataflow.model import validate_pair,difference,eval_difference,signature
from dataflow.moment import Counter,Budget,AnalysisLimit,histogram
from dataflow.producer import prove_upper
from dataflow.checker import check_equal,check_upper
from dataflow.literal import masks,traffic,execute,execute_resident
from dataflow.rewrites import apply_trace


def require(condition: bool, context) -> None:
    if not condition:
        raise RuntimeError(repr(context))


def random_pair(seed:int,index:int)->dict:
    r=random.Random(seed+index*104729);n=2+index%8
    ev=[gen.event(g,g,r.randrange(1+index%6),r.randrange(2)) for g in range(n)]
    for _ in range(r.randrange(1,2*n+1)):
        g=r.randrange(-1,n);ev.append(gen.event(g,n if g<0 else g,r.randrange(1+index%6),r.randrange(2)))
    kind='nm' if n%4==0 and index%3==0 else ('global' if index%3==1 else 'free')
    k=gen.kernel(n,ev,n+1,1+index%6,2,kind,n//2,list(range(n))+[-1]);N=len(ev)
    maps=[]
    for arm in range(2):
        order=list(range(N));r.shuffle(order);parts=[]
        for op in range(2):
            ng=r.randint(1,N);buckets=[[] for _ in range(ng)]
            for e in range(N):buckets[r.randrange(ng)].append(e)
            parts.append([x for x in buckets if x])
        maps.append(gen.mapping(k,order,parts,(['dense','bitmap','coordinate'][(index+arm)%3],'dense')))
    p=gen.pair(k,*maps)
    return gen.hierarchy(p,['dense','bitmap','coordinate'][index%3]) if index%3==2 else p


def cases(part:str):
    if part=='structured':
        for g,kind,fmt,h in itertools.product([1,2,3],['free','global','nm'],['dense','bitmap','coordinate'],[0,1]):
            p=gen.structured(g,kind,fmt)
            if h:p=gen.hierarchy(p,fmt)
            yield f'structured-{g}-{kind}-{fmt}-h{h}',p
    elif part=='grid':
        for b,kind in itertools.product([2,3,4],['free','global']):yield f'grid-{b}-{kind}',gen.grid(b,kind)
    elif part=='cycle':
        for n in range(3,13):yield f'cycle-{n}',gen.cycle(n)
    elif part=='format':
        for n in range(1,9):
            kinds=['free','global']+(['nm'] if n%4==0 else [])
            for a,b,used,kind in itertools.product(['dense','bitmap','coordinate'],['dense','bitmap','coordinate'],sorted({n,(n+1)//2}),kinds):
                yield f'format-{n}-{a}-{b}-{used}-{kind}',gen.format_change(n,a,b,used,kind)
    elif part.startswith('graph'):
        mode=part.split('-')[1];maxv=5 if mode=='free' else 4
        for n in range(1,maxv+1):
            possible=list(itertools.combinations(range(n),2))
            for code in range(1<<len(possible)):
                es=[e for i,e in enumerate(possible) if code>>i&1]
                yield f'graph-{mode}-{n}-{code}',gen.cut_graph(n,es,mode)
    elif part.startswith('random'):
        half=int(part.split('-')[1])
        for i in range(half*60,(half+1)*60):yield f'random-{i}',random_pair(79031,i)
    else:raise ValueError(part)


def check_case(name:str,p:dict)->dict:
    st=time.monotonic();cpu=time.process_time();admission=validate_pair(p);k=p['kernel'];levels=len(p['architecture']['capacity'])
    diffs=[difference(p,l) for l in range(levels)];cnt=Counter(k);N=cnt.avoid(0)
    qs=[cnt.square(c,t) for c,t in diffs];squares=[0]*levels;mn=[None]*levels;mx=[None]*levels;positive=[0]*levels;negative=[0]*levels
    numeric=0;seen=0
    values=[[(a*2654435761+tid*17+11)&0xffffffff for a in range(t['length'])] for tid,t in enumerate(k['tensors'])]
    for x in masks(k):
        source=traffic(p,'source',x,False);target=traffic(p,'target',x,False)
        for l,(c,terms) in enumerate(diffs):
            z = target[l] - source[l]
            require(z == eval_difference(c, terms, x), (name, 'signature', l, x))
            squares[l]+=z*z;mn[l]=z if mn[l] is None else min(mn[l],z);mx[l]=z if mx[l] is None else max(mx[l],z)
            positive[l]+=z>0;negative[l]+=z<0
        if N<=16 or seen<8:
            a,ca=execute_resident(p,'source',x,values);b,cb=execute_resident(p,'target',x,values)
            require(a == b == execute(k, p['source'], x, values), (name, 'semantics', x))
            require(ca == source and cb == target, (name, 'codec', x))
            numeric+=1
        seen+=1
    require(seen == N and squares == qs, (name, 'moment', seen, N))
    details=[]
    for l,(c,terms) in enumerate(diffs):
        proof=prove_upper(p,level=l);checked=check_upper(p,proof,l,proof['bound'])
        require(proof['bound'] == mx[l] and checked['exact'], (name, 'upper', l))
        if qs[l] == 0:
            require(check_equal(p, {'kind':'equal','level':l,'square_sum':0}, l)['accepted'], (name, 'equal', l))
        else:
            w = cnt.witness(c, terms)
            require(w is not None and eval_difference(c, terms, w) != 0, (name, 'witness', l))
        details.append({'level':l,'square_sum':qs[l],'min_delta':mn[l],'max_delta':mx[l],
                        'positive_masks':positive[l],'negative_masks':negative[l],
                        'terms':len(terms),'iid_histogram':histogram(terms),
                        **proof['statistics'],'attaining_mask':proof['witness']})
    if name.startswith('graph-'):
        parts=name.split('-');nv=int(parts[2]);code=int(parts[3]);possible=list(itertools.combinations(range(nv),2))
        edges=[e for i,e in enumerate(possible) if code>>i&1]
        expected=4*max(sum(((x>>a)^(x>>b))&1 for a,b in edges) for x in range(1<<nv))
        require(mx[0] == expected and p['architecture']['capacity'] == [8], (name, 'cut'))
        steps=[{'rule':'interchange','position':4*j+1,'slot_operands':[1]} for j in range(len(edges))]
        rewritten=apply_trace(k,p['architecture'],p['source'],steps)
        # Neutral events have one-use scopes; canonical retiming is unchanged.
        require(rewritten == p['target'], (name, 'rewrite realization'))
    if name.startswith('cycle-'):
        require(mx[0] == 4 and positive[0] == 1, (name, 'minimal witness'))
    if name.startswith('structured-') and '-nm-' in name:
        require(all(q == 0 for q in qs), (name, 'structured equality'))
    return {'case':name,'guards':k['guards'],'events':len(k['events']),'levels':levels,'legal_masks':N,
            'enumerated_masks':seen,'resident_numeric_masks':numeric,'capacity':p['architecture']['capacity'],
            'scopes_source':len(p['source']['scopes']),'scopes_target':len(p['target']['scopes']),
            'result':'passed','level_results':details,'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.monotonic()-st}


def main():
    pa=argparse.ArgumentParser();pa.add_argument('part',choices=['structured','grid','cycle','format','graph-free','graph-nm','random-0','random-1','random-2']);pa.add_argument('--out',type=Path,default=ROOT/'results');pa.add_argument('--inputs',type=Path,default=ROOT/'inputs');args=pa.parse_args()
    if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3));resource.setrlimit(resource.RLIMIT_CPU,(42,44))
    args.out.mkdir(parents=True,exist_ok=True);args.inputs.mkdir(parents=True,exist_ok=True)
    start=time.monotonic();cpu=time.process_time();rows=[]
    with (args.inputs/f'{args.part}.jsonl').open('w') as fi:
        for name,p in cases(args.part):
            fi.write(json.dumps({'case':name,'pair':p},separators=(',',':'))+'\n')
            rows.append(check_case(name,p))
    use=resource.getrusage(resource.RUSAGE_SELF)
    result={'part':args.part,'case_count':len(rows),'mask_count':sum(r['enumerated_masks'] for r in rows),
            'resident_numeric_masks':sum(r['resident_numeric_masks'] for r in rows),
            'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.monotonic()-start,
            'peak_rss_kib':use.ru_maxrss,'swap_events':use.ru_nswap,'workers':1,'rows':rows}
    (args.out/f'{args.part}.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))

if __name__=='__main__':main()
