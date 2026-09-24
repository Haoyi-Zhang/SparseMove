"""Trusted finite-IR admission and signature derivation.

All mappings refer to the SAME kernel and architecture. No schedule or sparsity
promise is obtained from a certificate. Arithmetic is the commutative ring of
32-bit unsigned integers; traffic uses declared fixed-width tensor slots.
"""
from collections import defaultdict
from typing import Any

class Invalid(ValueError):
    """Malformed or inadmissible input: no certificate may be accepted."""

MAX_GUARDS = 4096
MAX_EVENTS = 65536
MAX_SCOPES = 131072
MAX_LEVELS = 4

def integer(x: Any, lo: int, hi: int, what: str) -> int:
    if type(x) is not int or not lo <= x <= hi:
        raise Invalid(f'{what}: expected integer in [{lo}, {hi}]')
    return x

def keys(x: Any, expected: set[str], what: str) -> None:
    if type(x) is not dict or set(x) != expected:
        raise Invalid(f'{what}: unexpected or missing fields')

def vector(x: Any, maximum: int, what: str) -> list:
    if type(x) is not list or len(x) > maximum:
        raise Invalid(f'{what}: expected bounded list')
    return x

def validate_kernel(k: dict, arch: dict) -> None:
    keys(k, {'guards','blocks','tensors','outputs','events','arithmetic'}, 'kernel')
    n=integer(k['guards'],1,MAX_GUARDS,'guards')
    if k['arithmetic'] != 'mod32': raise Invalid('arithmetic: only mod32 is implemented')
    out=integer(k['outputs'],1,MAX_EVENTS,'outputs')
    tensors=vector(k['tensors'],64,'tensors')
    if not tensors: raise Invalid('no tensors')
    for t in tensors:
        keys(t,{'length','bytes','support'},'tensor')
        integer(t['length'],1,2**31-1,'tensor length')
        if t['bytes'] != 4 or type(t['bytes']) is not int:
            raise Invalid('mod32 tensor slots must have exactly 4 bytes')
        if t['support'] is not None:
            support=vector(t['support'],MAX_EVENTS,'tensor support')
            if len(support)!=t['length']:raise Invalid('tensor support/length mismatch')
            for g in support:integer(g,-1,n-1,'tensor support guard')
    events=vector(k['events'],MAX_EVENTS,'events')
    if not events: raise Invalid('empty kernel not in executable fragment')
    for e in events:
        keys(e,{'guard','output','reads'},'event')
        integer(e['guard'],-1,n-1,'guard')
        integer(e['output'],0,out-1,'output')
        reads=vector(e['reads'],8,'reads')
        if not reads: raise Invalid('empty product not in executable fragment')
        for r in reads:
            if type(r) is not list or len(r)!=2: raise Invalid('read shape')
            t=integer(r[0],0,len(tensors)-1,'tensor index')
            integer(r[1],0,tensors[t]['length']-1,'address')
            sp=tensors[t]['support']
            if sp is not None and sp[r[1]]>=0 and sp[r[1]]!=e['guard']:
                raise Invalid('event guard does not imply sparse operand presence')
    blocks=vector(k['blocks'],n,'blocks'); seen=set()
    for b in blocks:
        keys(b,{'ids','count'},'support block')
        ids=vector(b['ids'],n,'block ids')
        if not ids: raise Invalid('empty block')
        for i in ids:
            integer(i,0,n-1,'block guard')
            if i in seen: raise Invalid('overlapping or repeated block guard')
            seen.add(i)
        if b['count'] is not None: integer(b['count'],0,len(ids),'block count')
    if seen != set(range(n)): raise Invalid('blocks must partition all guards')
    keys(arch,{'capacity','control_capacity'},'architecture')
    cap=vector(arch['capacity'],MAX_LEVELS,'capacity')
    if not cap: raise Invalid('no hierarchy levels')
    for c in cap: integer(c,1,2**40,'payload capacity')
    ctl=integer(arch['control_capacity'],1,2**40,'control capacity')
    if ctl<(n+7)//8+4*out: raise Invalid('bitmap plus output accumulator reservation')

def validate_mapping(k: dict, arch: dict, m: dict) -> dict:
    keys(m,{'order','scopes','bindings'},'mapping')
    ecount=len(k['events']); levels=len(arch['capacity'])
    order=vector(m['order'],ecount,'order')
    if len(order)!=ecount: raise Invalid('event omission')
    for e in order: integer(e,0,ecount-1,'order event')
    if len(set(order))!=ecount: raise Invalid('not an event permutation')
    pos=[0]*ecount
    for p,e in enumerate(order):pos[e]=p
    scopes=vector(m['scopes'],MAX_SCOPES,'scopes')
    if not scopes:raise Invalid('no input residency')
    changes=[[] for _ in range(levels)]
    for s in scopes:
        keys(s,{'tensor','lo','hi','level','begin','end','parent','format'},'scope')
        t=integer(s['tensor'],0,len(k['tensors'])-1,'scope tensor')
        lo=integer(s['lo'],0,k['tensors'][t]['length']-1,'scope lo')
        hi=integer(s['hi'],lo+1,k['tensors'][t]['length'],'scope hi')
        lv=integer(s['level'],0,levels-1,'scope level')
        begin=integer(s['begin'],0,ecount-1,'scope begin')
        end=integer(s['end'],begin+1,ecount,'scope end')
        parent=integer(s['parent'],-1,len(scopes)-1,'scope parent')
        if (lv==0)!=(parent==-1): raise Invalid('root/parent mismatch')
        if s['format'] not in ('dense','bitmap','coordinate'):raise Invalid('unsupported tile format')
        if s['format']!='dense' and k['tensors'][t]['support'] is None:
            raise Invalid('packed format requires an explicit support map')
        b=reservation(s); changes[lv].extend([(begin,b),(end,-b)])
    for s in scopes:
        if s['parent']<0:continue
        p=scopes[s['parent']]
        if p['level']!=s['level']-1:raise Invalid('parent must be previous level')
        if p['tensor']!=s['tensor'] or not(p['lo']<=s['lo']<s['hi']<=p['hi']):
            raise Invalid('parent tile does not contain child')
        if not(p['begin']<=s['begin']<s['end']<=p['end']):
            raise Invalid('parent lifetime does not contain child')
    if sum(s['hi']-s['lo'] for s in scopes if s['format']!='dense')>200000:
        raise Invalid('packed-record expansion admission limit')
    peak=[]
    for lv,ch in enumerate(changes):
        live=high=0
        # Equal-time releases precede allocations, matching half-open intervals.
        for _,delta in sorted(ch):
            live+=delta;high=max(high,live)
            if live<0:raise Invalid('negative residency accounting')
        if live:raise Invalid('unreleased residency')
        if high>arch['capacity'][lv]:raise Invalid('payload capacity exceeded')
        peak.append(high)
    bind=vector(m['bindings'],ecount,'bindings')
    if len(bind)!=ecount:raise Invalid('binding/event mismatch')
    for ei,e in enumerate(k['events']):
        row=vector(bind[ei],8,'operand bindings')
        if len(row)!=len(e['reads']):raise Invalid('binding/operand mismatch')
        for (tid,addr),sid in zip(e['reads'],row):
            integer(sid,0,len(scopes)-1,'binding scope')
            s=scopes[sid]
            if s['level']!=levels-1 or s['tensor']!=tid or not(s['lo']<=addr<s['hi']):
                raise Invalid('binding does not provide declared operand')
            if not(s['begin']<=pos[ei]<s['end']):raise Invalid('use outside lifetime')
    return {'peak_payload_bytes':peak,'event_count':ecount,'scope_count':len(scopes)}

def validate_pair(pair: dict) -> dict:
    keys(pair,{'kernel','architecture','source','target'},'pair')
    k=pair['kernel'];a=pair['architecture'];validate_kernel(k,a)
    return {name:validate_mapping(k,a,pair[name]) for name in ('source','target')}

def support_ok(k: dict, x: int) -> bool:
    if type(x) is not int or x<0 or x>>k['guards']:return False
    for b in k['blocks']:
        if b['count'] is not None and sum((x>>i)&1 for i in b['ids'])!=b['count']:
            return False
    return True

def reservation(s:dict)->int:
    """Unconditional storage reservation, independent of the current mask."""
    return (8+8*(s['hi']-s['lo'])) if s['format']=='coordinate' else 4*(s['hi']-s['lo'])

def size_polynomial(k:dict,s:dict)->tuple[int,dict[int,int]]:
    """Encoded bytes = constant + sum_g packet_bytes[g] * x_g."""
    if s['format']=='dense':return 4*(s['hi']-s['lo']),{}
    const=8 if s['format']=='coordinate' else 0
    packet=8 if s['format']=='coordinate' else 4
    terms=defaultdict(int)
    for g in k['tensors'][s['tensor']]['support'][s['lo']:s['hi']]:
        if g<0:const+=packet
        else:terms[g]+=packet
    return const,dict(terms)

def signature(k: dict, m: dict, levels: int) -> tuple[list[int],list[dict[int,int]]]:
    """Derive exact signed OR terms, including mask-linear encoded transfers.

    x_g OR(A) = OR({g}) + OR(A) - OR(A union {g}).  Consequently even
    individually nonnegative packed-tile traffic may have signed coefficients.
    """
    scopes=m['scopes'];foot=[0]*len(scopes);always=[False]*len(scopes)
    for ei,e in enumerate(k['events']):
        for sid in m['bindings'][ei]:
            while sid>=0:
                if e['guard']<0:always[sid]=True
                else:foot[sid]|=1<<e['guard']
                sid=scopes[sid]['parent']
    constants=[(k['guards']+7)//8+4*k['outputs']]+[0]*(levels-1)
    terms=[defaultdict(int) for _ in range(levels)]
    for j,s in enumerate(scopes):
        h,packets=size_polynomial(k,s);lv=s['level'];a=foot[j]
        if always[j]:
            constants[lv]+=h
            for g,w in packets.items():terms[lv][1<<g]+=w
        elif a:
            terms[lv][a]+=h
            for g,w in packets.items():
                terms[lv][a]+=w;terms[lv][1<<g]+=w;terms[lv][a|(1<<g)]-=w
    return constants,[{a:w for a,w in t.items() if w} for t in terms]

def difference(pair: dict, level: int=0) -> tuple[int,list[tuple[int,int]]]:
    validate_pair(pair);levels=len(pair['architecture']['capacity'])
    integer(level,0,levels-1,'comparison level')
    a,aa=signature(pair['kernel'],pair['source'],levels)
    b,bb=signature(pair['kernel'],pair['target'],levels)
    d=defaultdict(int,bb[level])
    for g,w in aa[level].items():d[g]-=w
    return b[level]-a[level],sorted((g,w) for g,w in d.items() if w)

def eval_difference(c: int, terms: list[tuple[int,int]], x: int) -> int:
    return c+sum(w for a,w in terms if a&x)
