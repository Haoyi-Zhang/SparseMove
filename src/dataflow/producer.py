"""Untrusted exact frontier optimizer. The verifier does not import this file."""
import time
from .model import difference,integer,Invalid
from .moment import AnalysisLimit

def prove_upper(pair:dict,order:list[int]|None=None,level:int=0,
                max_layer:int=100000,max_total:int=300000,seconds:float=30.0)->dict:
    start=time.monotonic();k=pair['kernel'];n=k['guards'];c,terms=difference(pair,level)
    if n*len(terms)>2_000_000:raise AnalysisLimit('frontier incidence admission limit')
    if order is None:order=list(range(n))
    if type(order) is not list or len(order)!=n or any(type(v) is not int for v in order) or set(order)!=set(range(n)):
        raise Invalid('frontier order is not a guard permutation')
    pos={v:i for i,v in enumerate(order)}
    first=[];last=[]
    for mask,_ in terms:
        p=[pos[j] for j in range(n) if mask>>j&1];first.append(min(p));last.append(max(p))
    blocks=[];owner={}
    for b in k['blocks']:
        if b['count'] is None:continue
        ps=sorted(pos[v] for v in b['ids']);bid=len(blocks)
        blocks.append((ps,b['count']))
        for v in b['ids']:owner[v]=bid
    cur={(0,()):(0,0)};layers=[[[0,[],0]]];before=[];b_before=[]
    total=1;width=0;count_width=0
    for i,v in enumerate(order):
        after=[j for j in range(len(terms)) if first[j]<=i<last[j]]
        closing=[j for j in range(len(terms)) if last[j]==i]
        b_after=[j for j,(ps,_) in enumerate(blocks) if ps[0]<=i<ps[-1]]
        prev_index={j:p for p,j in enumerate(before)};b_index={j:p for p,j in enumerate(b_before)}
        nxt={}
        for (occ,counts),(val,mask) in cur.items():
            for bit in (0,1):
                newcounts={j:counts[p] for j,p in b_index.items()}
                if v in owner:
                    bid=owner[v];ps,want=blocks[bid];q=newcounts.get(bid,0)+bit
                    remaining=sum(p>i for p in ps)
                    if not(q<=want<=q+remaining):continue
                    newcounts[bid]=q
                def touched(j):
                    return ((occ>>prev_index[j])&1 if j in prev_index else 0) or (bit and (terms[j][0]>>v&1))
                newocc=sum(1<<p for p,j in enumerate(after) if touched(j))
                reward=sum(terms[j][1] for j in closing if touched(j))
                key=(newocc,tuple(newcounts.get(j,0) for j in b_after))
                candidate=(val+reward,mask|(bit<<v));old=nxt.get(key)
                if old is None or (candidate[0],-candidate[1])>(old[0],-old[1]):nxt[key]=candidate
                if len(nxt)>max_layer:raise AnalysisLimit('frontier layer state limit')
        if not nxt:raise Invalid('empty reachable frontier with nonempty promise')
        total+=len(nxt)
        if total>max_total or time.monotonic()-start>seconds:raise AnalysisLimit('frontier total/time limit')
        layers.append([[o,list(q),val] for (o,q),(val,_) in sorted(nxt.items())])
        cur=nxt;before=after;b_before=b_after;width=max(width,len(after));count_width=max(count_width,len(b_after))
    if set(cur)!={(0,())}:raise Invalid('nonempty final frontier')
    best,witness=cur[(0,())]
    return {'kind':'upper','level':level,'order':order,'bound':best+c,
            'witness':witness,'layers':layers,
            'statistics':{'terms':len(terms),'frontier_width':width,'open_count_blocks':count_width,
                          'total_states':total,'peak_states':max(len(z) for z in layers)}}
