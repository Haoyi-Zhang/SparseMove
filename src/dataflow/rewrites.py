"""Small, checked rewrite constructors for the declared immutable-input IR.

These are convenience constructors, NOT trusted optimizers. Every output is
re-admitted by the structural validator; traffic claims require their stated
side conditions or a separate equality/upper-bound certificate.
"""
from copy import deepcopy
from .model import Invalid,integer,validate_kernel,validate_mapping

def _admit(k,a,m):
    validate_kernel(k,a);validate_mapping(k,a,m);return m

def _leaf(k,a,m,sid):
    _admit(k,a,m);integer(sid,0,len(m['scopes'])-1,'rewrite scope')
    if m['scopes'][sid]['level']!=len(a['capacity'])-1:
        raise Invalid('this constructor rewrites leaf residencies only')

def merge(k:dict,a:dict,m:dict,left:int,right:int)->dict:
    """Merge two identical leaf tiles; hull lifetime must still fit capacity."""
    _leaf(k,a,m,left);_leaf(k,a,m,right)
    if left==right:raise Invalid('merge needs distinct scopes')
    left,right=sorted([left,right]);q=deepcopy(m);u=q['scopes'][left];v=q['scopes'][right]
    for key in ('tensor','lo','hi','level','parent','format'):
        if u[key]!=v[key]:raise Invalid('merge needs identical tile, format, and parent')
    u['begin']=min(u['begin'],v['begin']);u['end']=max(u['end'],v['end'])
    q['scopes'].pop(right)
    for row in q['bindings']:
        for i,sid in enumerate(row):row[i]=left if sid==right else sid-(sid>right)
    for s in q['scopes']:
        if s['parent']==right:raise Invalid('merged scope unexpectedly has a child')
        if s['parent']>right:s['parent']-=1
    return _admit(k,a,q)

def split(k:dict,a:dict,m:dict,sid:int,cut:int)->dict:
    """Partition one leaf tile. Coordinate headers can INCREASE traffic."""
    _leaf(k,a,m,sid);q=deepcopy(m);s=q['scopes'][sid]
    integer(cut,s['lo']+1,s['hi']-1,'split coordinate')
    other=deepcopy(s);other['lo']=cut;s['hi']=cut;new=len(q['scopes']);q['scopes'].append(other)
    for ei,row in enumerate(q['bindings']):
        for op,b in enumerate(row):
            if b==sid and k['events'][ei]['reads'][op][1]>=cut:row[op]=new
    return _admit(k,a,q)

def reencode(k:dict,a:dict,m:dict,sid:int,fmt:str)->dict:
    """Change one leaf encoding; semantic preservation alone implies no bound."""
    _leaf(k,a,m,sid);q=deepcopy(m);q['scopes'][sid]['format']=fmt
    return _admit(k,a,q)

def interchange(k:dict,a:dict,m:dict,position:int,slot_operands:list[int])->dict:
    """Swap adjacent events, retaining selected operand residencies by slot.

Other operand bindings move with their events. All used residency lifetimes are
retimed to their use hulls. Re-admission checks coverage, parents, and capacity.
This is the concrete four-event MAX-CUT rewrite, with slot_operands=[1].
"""
    _admit(k,a,m);integer(position,0,len(m['order'])-2,'interchange position')
    q=deepcopy(m);e,f=q['order'][position:position+2]
    if len(k['events'][e]['reads'])!=len(k['events'][f]['reads']):raise Invalid('different arities')
    if type(slot_operands) is not list or len(set(slot_operands))!=len(slot_operands):
        raise Invalid('slot operands must be a list without duplicates')
    for op in slot_operands:
        integer(op,0,len(q['bindings'][e])-1,'slot operand')
        q['bindings'][e][op],q['bindings'][f][op]=q['bindings'][f][op],q['bindings'][e][op]
    q['order'][position:position+2]=[f,e]
    uses=[[] for _ in q['scopes']]
    for p,ei in enumerate(q['order']):
        for sid in q['bindings'][ei]:
            while sid>=0:uses[sid].append(p);sid=q['scopes'][sid]['parent']
    # Unused reservations retain their old lifetime. A resulting parent conflict
    # is rejected, not silently fixed with an unmodelled allocation policy.
    for s,ps in zip(q['scopes'],uses):
        if ps:s['begin']=min(ps);s['end']=max(ps)+1
    return _admit(k,a,q)

def apply_trace(k:dict,a:dict,m:dict,trace:list[dict])->dict:
    """A bounded data-only rewrite trace; no eval, imports, or user code."""
    if type(trace) is not list or len(trace)>1024:raise Invalid('trace length')
    q=deepcopy(m)
    for step in trace:
        if type(step) is not dict or 'rule' not in step:raise Invalid('trace step')
        name=step['rule']
        if name=='merge' and set(step)=={'rule','left','right'}:q=merge(k,a,q,step['left'],step['right'])
        elif name=='split' and set(step)=={'rule','scope','cut'}:q=split(k,a,q,step['scope'],step['cut'])
        elif name=='reencode' and set(step)=={'rule','scope','format'}:q=reencode(k,a,q,step['scope'],step['format'])
        elif name=='interchange' and set(step)=={'rule','position','slot_operands'}:
            q=interchange(k,a,q,step['position'],step['slot_operands'])
        else:raise Invalid('unknown or malformed rewrite')
    return q
