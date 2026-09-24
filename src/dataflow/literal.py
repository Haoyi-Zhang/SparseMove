"""Literal operational evaluator, intentionally separate from signatures/DP.

It visits events, tests guards, loads an uninitialized scope once, and sums
products in the declared arithmetic. It never calls the footprint extractor.
"""
from .model import validate_pair,support_ok,Invalid

def traffic(pair:dict,which:str,x:int,admit:bool=True)->list[int]:
    if admit:validate_pair(pair)
    k=pair['kernel'];m=pair[which]
    if not support_ok(k,x):raise Invalid('mask violates the declared support promise')
    result=[(k['guards']+7)//8+4*k['outputs']]+[0]*(len(pair['architecture']['capacity'])-1)
    loaded=set()
    for position,ei in enumerate(m['order']):
        e=k['events'][ei]
        if e['guard']>=0 and not((x>>e['guard'])&1):continue
        for operand,sid in enumerate(m['bindings'][ei]):
            chain=[]
            while sid>=0:
                chain.append(sid);sid=m['scopes'][sid]['parent']
            for sid in reversed(chain):
                s=m['scopes'][sid]
                if not(s['begin']<=position<s['end']):raise Invalid('operational use after lifetime')
                if sid not in loaded:
                    result[s['level']]+=encoded_bytes(k,s,x);loaded.add(sid)
    return result

def execute(k:dict,m:dict,x:int,values:list[list[int]])->list[int]:
    if not support_ok(k,x):raise Invalid('illegal numeric-test mask')
    if len(values)!=len(k['tensors']) or any(len(v)!=t['length'] for v,t in zip(values,k['tensors'])):
        raise Invalid('numeric input shape')
    if any(type(v) is not int or not 0<=v<2**32 for t in values for v in t):
        raise Invalid('numeric input not mod32')
    out=[0]*k['outputs']
    for ei in m['order']:
        e=k['events'][ei]
        if e['guard']>=0 and not(x>>e['guard']&1):continue
        product=1
        for tid,a in e['reads']:product=(product*values[tid][a])%(2**32)
        out[e['output']]=(out[e['output']]+product)%(2**32)
    return out

def masks(k:dict,limit:int=1_000_000):
    """Independent Cartesian-product oracle, exponential by design."""
    from itertools import combinations,product
    from math import comb
    from .moment import AnalysisLimit
    count=1
    for b in k['blocks']:
        count*=2**len(b['ids']) if b['count'] is None else comb(len(b['ids']),b['count'])
        if count>limit:raise AnalysisLimit('exhaustive oracle mask limit')
    options=[]
    for b in k['blocks']:
        ids=b['ids'];want=b['count'];row=[]
        sizes=range(len(ids)+1) if want is None else [want]
        for size in sizes:
            for combo in combinations(ids,size):row.append(sum(1<<i for i in combo))
        options.append(row)
    for xs in product(*options):yield sum(xs)


def encoded_bytes(k:dict,s:dict,x:int)->int:
    """Literal format byte count; does not call the signature size polynomial."""
    if s['format']=='dense':return 4*(s['hi']-s['lo'])
    count=0
    support=k['tensors'][s['tensor']]['support']
    for address in range(s['lo'],s['hi']):
        g=support[address]
        if g<0 or ((x>>g)&1):count+=1
    if s['format']=='bitmap':return 4*count
    if s['format']=='coordinate':return 8+8*count
    raise Invalid('unknown literal format')

def encode(k:dict,s:dict,x:int,values:list[int])->bytes:
    """Small codec oracle. Bitmap packing uses the already resident mask."""
    import struct
    t=k['tensors'][s['tensor']];support=t['support'];entries=[]
    for a in range(s['lo'],s['hi']):
        g=-1 if support is None else support[a]
        present=g<0 or ((x>>g)&1)
        if s['format']=='dense':entries.append(struct.pack('<I',values[a] if present else 0))
        elif present:
            entries.append(struct.pack('<II',a,values[a]) if s['format']=='coordinate' else struct.pack('<I',values[a]))
    head=struct.pack('<II',s['lo'],len(entries)) if s['format']=='coordinate' else b''
    return head+b''.join(entries)

def decode(k:dict,s:dict,x:int,data:bytes)->dict[int,int]:
    import struct
    support=k['tensors'][s['tensor']]['support'];answer={};pos=0
    if s['format']=='coordinate':
        lo,count=struct.unpack_from('<II',data,0);pos=8
        if lo!=s['lo'] or len(data)!=8+8*count:raise Invalid('coordinate header')
    for a in range(s['lo'],s['hi']):
        g=-1 if support is None else support[a];present=g<0 or ((x>>g)&1)
        if s['format']=='dense' or present:
            if s['format']=='coordinate':
                got,val=struct.unpack_from('<II',data,pos);pos+=8
                if got!=a:raise Invalid('coordinate record')
            else:val=struct.unpack_from('<I',data,pos)[0];pos+=4
            answer[a]=val
        else:answer[a]=0
    if pos!=len(data):raise Invalid('unconsumed tile bytes')
    return answer


def execute_resident(pair:dict,which:str,x:int,values:list[list[int]])->tuple[list[int],list[int]]:
    """End-to-end codec oracle, not a performance or physical-memory simulator.

    Child tiles are encoded from their decoded parent's logical values. This
    checks format conversion and bindings instead of reading original arrays
    directly at every arithmetic event. Python dictionaries are oracle state,
    not a claim about the hardware implementation of compressed random access.
    """
    validate_pair(pair)
    k=pair['kernel'];m=pair[which]
    if not support_ok(k,x):raise Invalid('illegal resident-execution mask')
    # Reuse shape/range checks; the returned schedule result is not the oracle.
    execute(k,m,x,values)
    loaded={};out=[0]*k['outputs']
    costs=[(k['guards']+7)//8+4*k['outputs']]+[0]*(len(pair['architecture']['capacity'])-1)
    for pos,ei in enumerate(m['order']):
        e=k['events'][ei]
        if e['guard']>=0 and not(x>>e['guard']&1):continue
        product=1
        for (tid,address),sid in zip(e['reads'],m['bindings'][ei]):
            chain=[];leaf=sid
            while sid>=0:chain.append(sid);sid=m['scopes'][sid]['parent']
            for sid in reversed(chain):
                s=m['scopes'][sid]
                if not s['begin']<=pos<s['end']:raise Invalid('resident lifetime')
                if sid not in loaded:
                    parent=s['parent']
                    logical=values[tid] if parent<0 else loaded[parent]
                    raw=encode(k,s,x,logical)
                    loaded[sid]=decode(k,s,x,raw);costs[s['level']]+=len(raw)
            product=(product*loaded[leaf][address])%(2**32)
        out[e['output']]=(out[e['output']]+product)%(2**32)
    return out,costs
