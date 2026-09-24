"""Owned deterministic finite kernels and mappings; no trained models or data.

Generators describe scientific input families, not claims of application breadth.
"""
from copy import deepcopy
from .model import reservation,validate_pair


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)

def blocks(n:int,kind:str='free',count:int|None=None)->list[dict]:
    if kind=='nm':
        _require(n % 4 == 0, 'nm blocks require a guard count divisible by four')
        return [{'ids':list(range(j,j+4)),'count':2} for j in range(0,n,4)]
    return [{'ids':list(range(n)),'count':None if kind=='free' else count}]

def kernel(n,events,alen,blen,outputs=1,promise='free',count=None,support=None):
    return {'guards':n,'blocks':blocks(n,promise,count),
            'tensors':[{'length':alen,'bytes':4,'support':list(range(n)) if support is None else support},
                       {'length':blen,'bytes':4,'support':None}],
            'outputs':outputs,'events':events,'arithmetic':'mod32'}

def event(g,a,b=0,out=0):return {'guard':g,'output':out,'reads':[[0,a],[1,b]]}

def mapping(k,order,parts,formats=('dense','dense'),extents=('hull','hull')):
    position={e:i for i,e in enumerate(order)};scopes=[];binding=[[-1,-1] for _ in k['events']]
    for op,groups in enumerate(parts):
        for group in groups:
            _require(bool(group), 'mapping groups must be nonempty')
            accesses=[k['events'][e]['reads'][op] for e in group];tid=accesses[0][0]
            _require(all(t == tid for t, _ in accesses), 'one mapping group cannot mix tensors')
            lo=min(a for t,a in accesses);hi=max(a for t,a in accesses)+1
            if extents[op]=='full':lo=0;hi=k['tensors'][tid]['length']
            sid=len(scopes)
            scopes.append({'tensor':tid,'lo':lo,'hi':hi,'level':0,
                           'begin':min(position[e] for e in group),'end':max(position[e] for e in group)+1,
                           'parent':-1,'format':formats[op]})
            for e in group:
                _require(binding[e][op] < 0, 'an event operand cannot be bound twice')
                binding[e][op] = sid
    return {'order':order,'scopes':scopes,'bindings':binding}

def pair(k,source,target,capacity=None):
    if capacity is None:
        L=1+max(s['level'] for m in [source,target] for s in m['scopes']);capacity=[0]*L
        for m in [source,target]:
            for lv in range(L):
                changes=[]
                for s in m['scopes']:
                    if s['level']==lv:changes.extend([(s['begin'],reservation(s)),(s['end'],-reservation(s))])
                live=0
                for _,d in sorted(changes):live+=d;capacity[lv]=max(capacity[lv],live)
    p={'kernel':k,'architecture':{'capacity':capacity,'control_capacity':(k['guards']+7)//8+4*k['outputs']},'source':source,'target':target}
    validate_pair(p);return p

def structured(groups:int,promise:str='nm',fmt:str='dense')->dict:
    n=4*groups;events=[]
    for j in range(groups):
        for i in range(4):
            for f in range(2):events.append(event(4*j+i,4*j+i,2*i+f,2*j+f))
    k=kernel(n,events,n,8,2*groups,promise,n//2)
    ar=[[8*j+t for t in range(8)] for j in range(groups)]
    bs=[[8*j+2*i+f for f in range(2)] for j in range(groups) for i in range(4)]
    bt=[[8*j+2*i+f for i in range(4)] for j in range(groups) for f in range(2)]
    s=mapping(k,list(range(8*groups)),[ar,bs],(fmt,'dense'),('hull','full'))
    t=mapping(k,[e for group in bt for e in group],[ar,bt],(fmt,'dense'),('hull','full'))
    return pair(k,s,t)

def grid(side:int,promise:str='free')->dict:
    n=side*side;k=kernel(n,[event(g,g) for g in range(n)],n,1,promise=promise,count=side)
    a=[[e] for e in range(n)];r=[list(range(j*side,(j+1)*side)) for j in range(side)];c=[list(range(j,n,side)) for j in range(side)]
    s=mapping(k,list(range(n)),[a,r]);t=mapping(k,[e for group in c for e in group],[a,c])
    return pair(k,s,t,[8])

def cycle(n:int)->dict:
    _require(n >= 3, 'cycle requires at least three guards')
    ev=[]
    for j in range(n):ev.extend([event((j-1)%n,(j-1)%n),event(j,j)])
    k=kernel(n,ev,n,1);a=[[e] for e in range(2*n)]
    sgroups=[[2*j,2*j+1] for j in range(n)]
    tgroups=[[2*j+1] for j in range(n)]+[[2*j for j in range(n)]]
    s=mapping(k,list(range(2*n)),[a,sgroups]);t=mapping(k,[e for g in tgroups for e in g],[a,tgroups])
    return pair(k,s,t,[8])

def cut_graph(vertices:int,edges:list[tuple[int,int]],promise:str='free')->dict:
    """Four-event local swap per edge: delta/4 equals the graph cut size."""
    structured_promise=promise=='nm';n=4*vertices if structured_promise else vertices
    gids=[4*j if structured_promise else j for j in range(vertices)]
    ev=[];sg=[];tg=[]
    for u,v in edges:
        _require(0 <= u < v < vertices, 'edges must be canonical in-range pairs')
        base=len(ev);u=gids[u];v=gids[v]
        ev.extend([event(u,u),event(u,u),event(v,v),event(v,v)])
        sg.extend([[base,base+1],[base+2,base+3]])
        tg.extend([[base,base+2],[base+1,base+3]])
    # Each dummy guard occurs in an identical neutral event in both schedules.
    if structured_promise:
        for j in range(n):
            if j%4:
                e=len(ev);ev.append(event(j,j));sg.append([e]);tg.append([e])
    used={e['guard'] for e in ev}
    for j in range(n):
        if j not in used:
            e=len(ev);ev.append(event(j,j));sg.append([e]);tg.append([e])
    k=kernel(n,ev,n,1,promise=promise);a=[[e] for e in range(len(ev))]
    s=mapping(k,[e for g in sg for e in g],[a,sg]);t=mapping(k,[e for g in tg for e in g],[a,tg])
    return pair(k,s,t,[8])

def cut_threshold(vertices:int,edges:list[tuple[int,int]],threshold:int,promise:str='free')->dict:
    """Max-Cut threshold gadget with the requested universal bound fixed at zero.

    For a graph G and integer L=threshold in [1, |E|], target-source traffic is
    4*(cut_G(S)-(L-1)).  Hence every legal mask has delta <= 0 exactly when
    maxcut(G) < L.  The (L-1) offset units use two unconditional events: source
    reloads the dense B word, while target retains it.  Both arms keep one
    four-byte A word and one four-byte B word live, so payload capacity stays 8.
    """
    _require(isinstance(threshold, int) and not isinstance(threshold, bool), 'threshold must be an integer')
    _require(1 <= threshold <= len(edges), 'threshold must be in [1, |E|]')
    structured_promise=promise=='nm';n=4*vertices if structured_promise else vertices
    gids=[4*j if structured_promise else j for j in range(vertices)]
    ev=[];sg=[];tg=[]
    for u,v in edges:
        _require(0 <= u < v < vertices, 'edges must be canonical in-range pairs')
        base=len(ev);u=gids[u];v=gids[v]
        ev.extend([event(u,u),event(u,u),event(v,v),event(v,v)])
        sg.extend([[base,base+1],[base+2,base+3]])
        tg.extend([[base,base+2],[base+1,base+3]])
    # Each offset unit contributes -4 bytes: two source B loads versus one target load.
    always=n
    for _ in range(threshold-1):
        base=len(ev)
        ev.extend([event(-1,always),event(-1,always)])
        sg.extend([[base],[base+1]])
        tg.append([base,base+1])
    # Each dummy guard occurs in an identical neutral event in both schedules.
    if structured_promise:
        for j in range(n):
            if j%4:
                e=len(ev);ev.append(event(j,j));sg.append([e]);tg.append([e])
    used={e['guard'] for e in ev if e['guard']>=0}
    for j in range(n):
        if j not in used:
            e=len(ev);ev.append(event(j,j));sg.append([e]);tg.append([e])
    support=list(range(n))+[-1]
    k=kernel(n,ev,n+1,1,promise=promise,support=support);a=[[e] for e in range(len(ev))]
    s=mapping(k,[e for g in sg for e in g],[a,sg]);t=mapping(k,[e for g in tg for e in g],[a,tg])
    return pair(k,s,t,[8])

def hierarchy(p:dict,root_format:str='dense')->dict:
    p=deepcopy(p);k=p['kernel'];N=len(k['events'])
    for name in ['source','target']:
        m=p[name];old=len(m['scopes'])
        for s in m['scopes']:s['level']=1;s['parent']=old+s['tensor']
        for tid,t in enumerate(k['tensors']):
            m['scopes'].append({'tensor':tid,'lo':0,'hi':t['length'],'level':0,'begin':0,'end':N,'parent':-1,
                                'format':root_format if t['support'] is not None else 'dense'})
    return pair(k,p['source'],p['target'])

def format_change(guards:int,source_fmt:str,target_fmt:str,used:int|None=None,promise:str='free')->dict:
    """Same tile/use order, changed dense/bitmap/coordinate representation.

    Unused guards can still contribute packets to an overfetched packed tile.
    """
    if used is None:used=guards
    ev=[event(g,g) for g in range(used)];k=kernel(guards,ev,guards,1,promise=promise,count=guards//2)
    a=[list(range(used))];b=[list(range(used))];order=list(range(used))
    s=mapping(k,order,[a,b],(source_fmt,'dense'),('full','full'))
    t=mapping(k,order,[a,b],(target_fmt,'dense'),('full','full'))
    return pair(k,s,t)
