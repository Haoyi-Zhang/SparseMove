"""Bounded, fail-closed command-line interface; input and certificates are JSON."""
import argparse,json,os,sys,resource,tempfile
from pathlib import Path
from .model import Invalid,validate_pair,difference,eval_difference
from .moment import Counter,Budget,AnalysisLimit
from .producer import prove_upper
from .checker import check_equal,check_upper
from .literal import traffic

MAX_FILE=16*1024*1024

def read_json(path:str):
    p=Path(path)
    if not p.is_file() or p.stat().st_size>MAX_FILE:raise Invalid('input is not a regular file <=16 MiB')
    def unique(pairs):
        obj={}
        for k,v in pairs:
            if k in obj:raise Invalid('duplicate JSON key')
            obj[k]=v
        return obj
    with p.open(encoding='utf-8') as f:return json.load(f,object_pairs_hook=unique)

def save_json(path:str,obj):
    # Serialize before publication, bound the round-trip representation, and
    # publish without replacing an existing path. The temporary file is local
    # to the target directory; a failed publication leaves no partial output.
    data=(json.dumps(obj,separators=(',',':'))+'\n').encode('utf-8')
    if len(data)>MAX_FILE:raise AnalysisLimit('certificate exceeds 16 MiB file limit')
    target=Path(path);tmp=None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent,prefix='.proof-',delete=False) as f:
            tmp=Path(f.name);f.write(data);f.flush();os.fsync(f.fileno())
        os.link(tmp,target)  # Atomic creation; fails if target already exists.
    finally:
        if tmp is not None:tmp.unlink(missing_ok=True)

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['validate','equal','upper','check-equal','check-upper','trace'])
    parser.add_argument('pair');parser.add_argument('--level',type=int,default=0)
    parser.add_argument('--certificate');parser.add_argument('--output');parser.add_argument('--bound',type=int)
    parser.add_argument('--mask',type=int);parser.add_argument('--seconds',type=float,default=30)
    parser.add_argument('--max-layer',type=int,default=100000);parser.add_argument('--max-total',type=int,default=300000)
    args=parser.parse_args()
    if not 0<args.seconds<=40 or not 1<=args.max_layer<=100000 or not 1<=args.max_total<=300000:
        parser.error('seconds in (0,40], layer <=100000, total <=300000 required')
    # One process, 1 GiB address-space cap, <=44 CPU seconds. No child processes.
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(43,44))
    if hasattr(os,'sched_getaffinity'):
        available=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,set(available[:1]))
    try:
        p=read_json(args.pair);cert=None
        if args.action=='validate':result={'admitted':validate_pair(p)}
        elif args.action=='equal':
            c,terms=difference(p,args.level);counter=Counter(p['kernel']);budget=Budget(seconds=args.seconds)
            q=counter.square(c,terms,budget=budget)
            if q==0:
                cert={'kind':'equal','level':args.level,'square_sum':0}
                result=check_equal(p,cert,args.level,Budget(seconds=args.seconds))
            else:
                x=counter.witness(c,terms,budget=budget)
                result={'accepted':False,'claim':'equal','square_sum':q,'counterexample':x,'delta_bytes':eval_difference(c,terms,x)}
        elif args.action=='upper':
            cert=prove_upper(p,level=args.level,max_layer=args.max_layer,max_total=args.max_total,seconds=args.seconds)
            result=check_upper(p,cert,args.level,cert['bound'],args.max_layer,args.max_total,args.seconds)
        elif args.action.startswith('check-'):
            if not args.certificate:raise Invalid('--certificate is required')
            cert=read_json(args.certificate)
            if args.action=='check-equal':result=check_equal(p,cert,args.level,Budget(seconds=args.seconds))
            else:
                if args.bound is None:raise Invalid('--bound must be supplied independently')
                result=check_upper(p,cert,args.level,args.bound,args.max_layer,args.max_total,args.seconds)
        else:
            if args.mask is None:raise Invalid('--mask is required')
            result={name:traffic(p,name,args.mask) for name in ['source','target']}
        if args.output:
            if cert is None:raise Invalid('no certificate produced; no output written')
            save_json(args.output,cert)
        print(json.dumps(result,separators=(',',':')));return 0
    except (AnalysisLimit,MemoryError) as exc:
        print(json.dumps({'accepted':False,'status':'unresolved','reason':str(exc) or 'memory limit'}));return 2
    except (Invalid,ValueError,TypeError,KeyError,IndexError,OSError,RecursionError) as exc:
        print(json.dumps({'accepted':False,'status':'rejected','reason':str(exc)}));return 1

if __name__=='__main__':raise SystemExit(main())
