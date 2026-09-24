"""One-sided potential verifier with an independently written transition loop.

Trusted components: finite-IR validator, signature extraction, exact integer
arithmetic, this recurrence, and Python runtime. This is not a proof assistant.
The certificate is data, never executable code. Requested bounds are arguments,
not trusted claims imported from the certificate.
"""
import time
from .model import difference,keys,integer,Invalid,support_ok,eval_difference
from .moment import Counter,Budget,AnalysisLimit

def check_equal(pair:dict,certificate:dict,level:int=0,budget:Budget|None=None)->dict:
    keys(certificate,{'kind','level','square_sum'},'equality certificate')
    if certificate['kind']!='equal' or type(certificate['level']) is not int or certificate['level']!=level:
        raise Invalid('equality claim mismatch')
    if type(certificate['square_sum']) is not int or certificate['square_sum']!=0:raise Invalid('equality needs zero')
    c,terms=difference(pair,level);counter=Counter(pair['kernel'])
    if counter.square(c,terms,budget=budget)!=0:raise Invalid('not equal on declared support family')
    return {'accepted':True,'claim':'equal','level':level,'legal_masks':counter.avoid(0)}

def check_upper(pair:dict,certificate:dict,level:int,bound:int,
                max_layer:int=100000,max_total:int=300000,seconds:float=30.0)->dict:
    begin=time.monotonic();constant,terms=difference(pair,level);k=pair['kernel'];n=k['guards']
    if n*len(terms)>2_000_000:raise AnalysisLimit('frontier incidence admission limit')
    integer(bound,-2**63,2**63-1,'requested bound')
    keys(certificate,{'kind','level','order','bound','witness','layers','statistics'},'upper certificate')
    if certificate['kind']!='upper' or type(certificate['level']) is not int or certificate['level']!=level:
        raise Invalid('upper claim mismatch')
    if type(certificate['bound']) is not int or certificate['bound']!=bound:raise Invalid('requested bound differs')
    order=certificate['order']
    if type(order) is not list or len(order)!=n or any(type(v) is not int for v in order) or sorted(order)!=list(range(n)):
        raise Invalid('invalid variable order')
    rank={v:i for i,v in enumerate(order)}
    members=[{rank[v] for v in range(n) if a&(1<<v)} for a,_ in terms]
    fstarts=[min(s) for s in members];fends=[max(s) for s in members]
    cb=[]
    for block in k['blocks']:
        if block['count'] is not None:cb.append(({rank[v] for v in block['ids']},block['count']))
    # Each layer describes the frontier immediately before order[layer].
    ff=[[j for j in range(len(terms)) if fstarts[j]<t<=fends[j]] for t in range(n+1)]
    bb=[[j for j,(ps,_) in enumerate(cb) if min(ps)<t<=max(ps)] for t in range(n+1)]
    layers=certificate['layers']
    if type(layers) is not list or len(layers)!=n+1:raise Invalid('layer count')
    tables=[];total=0
    for t,rows in enumerate(layers):
        if type(rows) is not list or not rows or len(rows)>max_layer:raise Invalid('layer size')
        table={};total+=len(rows)
        if total>max_total:raise AnalysisLimit('verifier total state limit')
        for row in rows:
            if type(row) is not list or len(row)!=3:raise Invalid('state row')
            occ,counts,potential=row
            integer(occ,0,(1<<len(ff[t]))-1,'occupancy')
            if type(counts) is not list or len(counts)!=len(bb[t]):raise Invalid('count frontier arity')
            for q,j in zip(counts,bb[t]):integer(q,0,cb[j][1],'count state')
            integer(potential,-2**63,2**63-1,'potential')
            key=(occ,tuple(counts))
            if key in table:raise Invalid('duplicate state')
            table[key]=potential
        tables.append(table)
    if tables[0]!={(0,()):0}:raise Invalid('initial potential')
    for t,v in enumerate(order):
        previous=ff[t];following=ff[t+1];closed=[j for j in range(len(terms)) if fends[j]==t]
        for (occupancy,count_tuple),value in tables[t].items():
            occupied={j for p,j in enumerate(previous) if occupancy&(1<<p)}
            counts=dict(zip(bb[t],count_tuple))
            for bit in [0,1]:
                nextcounts=counts.copy();possible=True
                for j,(positions,want) in enumerate(cb):
                    if t in positions:
                        now=counts.get(j,0)+bit
                        left=len([z for z in positions if z>t])
                        if now>want or now+left<want:possible=False;break
                        nextcounts[j]=now
                if not possible:continue
                active=occupied.copy()
                if bit:
                    active.update(j for j,maskpositions in enumerate(members) if t in maskpositions)
                nextocc=sum(1<<p for p,j in enumerate(following) if j in active)
                key=(nextocc,tuple(nextcounts.get(j,0) for j in bb[t+1]))
                gain=sum(terms[j][1] for j in closed if j in active)
                if key not in tables[t+1]:raise Invalid('missing reachable successor')
                if tables[t+1][key]<value+gain:raise Invalid('violated potential inequality')
        if time.monotonic()-begin>seconds:raise AnalysisLimit('verifier time limit')
    if set(tables[-1])!={(0,())}:raise Invalid('terminal frontier')
    if tables[-1][(0,())]+constant>bound:raise Invalid('terminal bound exceeded')
    witness=certificate['witness'];exact=False
    if witness is not None:
        if not support_ok(k,witness):raise Invalid('illegal attaining mask')
        if eval_difference(constant,terms,witness)!=bound:raise Invalid('mask does not attain requested bound')
        exact=True
    # Statistics are informational and must not influence acceptance.
    return {'accepted':True,'claim':'upper','level':level,'bound':bound,'exact':exact,
            'checked_states':total,'attaining_mask':witness}
