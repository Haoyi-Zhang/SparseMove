"""Exact sum-of-squares over a product of cardinality blocks.

The identity is elementary second-moment algebra, NOT a new probability law.
It is used here as a complete conditional equality test for residency traffic.
No floating point, random masks, or external solver is used.
"""
import math,time
from dataclasses import dataclass
from .model import Invalid,integer,eval_difference

class AnalysisLimit(RuntimeError):
    """The configured analysis envelope was exceeded; result is unresolved."""

@dataclass
class Budget:
    operations: int=50_000_000
    seconds: float=30.0
    used: int=0
    def __post_init__(self):self.start=time.monotonic()
    def charge(self,n:int)->None:
        self.used+=n
        if self.used>self.operations or time.monotonic()-self.start>self.seconds:
            raise AnalysisLimit('exact analysis budget exceeded')

class Counter:
    def __init__(self,k:dict):
        self.n=k['guards'];self.fixed=[];self.free=0
        for b in k['blocks']:
            mask=sum(1<<i for i in b['ids'])
            if b['count'] is None:self.free|=mask
            else:self.fixed.append((mask,b['count']))
    def avoid(self,a:int,ones:int=0,zeros:int=0)->int:
        if ones&zeros or a&ones:return 0
        available=~(ones|zeros|a)
        z=1<<((self.free&available).bit_count())
        for mask,k in self.fixed:
            need=k-(mask&ones).bit_count(); room=(mask&available).bit_count()
            if need<0 or need>room:return 0
            z*=math.comb(room,need)
        return z
    def square(self,c:int,terms:list[tuple[int,int]],ones:int=0,zeros:int=0,budget:Budget|None=None)->int:
        if budget is None:budget=Budget()
        m=len(terms);budget.charge((1+m+m*(m+1)//2)*(1+len(self.fixed)))
        D=c+sum(w for _,w in terms);q=D*D*self.avoid(0,ones,zeros)
        singles=[self.avoid(a,ones,zeros) for a,_ in terms]
        q-=2*D*sum(w*z for (_,w),z in zip(terms,singles))
        for i,(a,w) in enumerate(terms):
            q+=w*w*singles[i]
            for b,v in terms[:i]:q+=2*w*v*self.avoid(a|b,ones,zeros)
        if q<0:raise Invalid('negative exact square sum: internal inconsistency')
        budget.charge(0)
        return q
    def witness(self,c:int,terms:list[tuple[int,int]],budget:Budget|None=None)->int|None:
        if budget is None:budget=Budget()
        if self.square(c,terms,budget=budget)==0:return None
        ones=zeros=0
        for i in range(self.n):
            z=zeros|(1<<i)
            if self.square(c,terms,ones,z,budget)>0:zeros=z
            else:ones|=1<<i
        if self.avoid(0,ones,zeros)!=1 or eval_difference(c,terms,ones)==0:
            raise Invalid('counterexample self-reduction consistency failure')
        return ones

def histogram(terms:list[tuple[int,int]])->dict[int,int]:
    """Signed iid-density histogram. Zero is NOT universal cost equality."""
    h={}
    for a,w in terms:h[a.bit_count()]=h.get(a.bit_count(),0)+w
    return {a:w for a,w in h.items() if w}
