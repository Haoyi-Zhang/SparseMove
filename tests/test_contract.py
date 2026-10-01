"""Self-contained validation of the declared IR and certificate boundary."""
import copy,itertools,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from dataflow import generate as G
from dataflow.model import Invalid,validate_pair,difference,eval_difference,support_ok,signature
from dataflow.moment import Counter,Budget,AnalysisLimit,histogram
from dataflow.producer import prove_upper
from dataflow.checker import check_upper,check_equal
from dataflow.literal import masks,traffic,execute,execute_resident,encode,decode
from dataflow.rewrites import merge,split,reencode,interchange,apply_trace
from dataflow.__main__ import read_json,save_json

ROOT=Path(__file__).resolve().parents[1]

class Contract(unittest.TestCase):
    def assert_invalid_pair(self,change):
        p=G.structured(1);change(p)
        with self.assertRaises((Invalid,TypeError,ValueError,KeyError)):validate_pair(p)

    def test_admission_mutations(self):
        mutations=[
          ('omit_event',lambda p:p['source']['order'].pop()),
          ('duplicate_event',lambda p:p['source']['order'].__setitem__(0,1)),
          ('invalid_event',lambda p:p['target']['order'].__setitem__(0,999)),
          ('boolean_event',lambda p:p['source']['order'].__setitem__(0,False)),
          ('missing_binding',lambda p:p['source']['bindings'].pop()),
          ('wrong_binding_arity',lambda p:p['target']['bindings'][0].pop()),
          ('wrong_tensor',lambda p:p['source']['scopes'][0].__setitem__('tensor',1)),
          ('short_lifetime',lambda p:p['source']['scopes'][0].__setitem__('end',1)),
          ('reversed_tile',lambda p:p['source']['scopes'][0].__setitem__('hi',0)),
          ('insufficient_payload',lambda p:p['architecture']['capacity'].__setitem__(0,47)),
          ('insufficient_control',lambda p:p['architecture'].__setitem__('control_capacity',8)),
          ('overlap_blocks',lambda p:p['kernel']['blocks'][0]['ids'].append(0)),
          ('missing_guard',lambda p:p['kernel']['blocks'][0]['ids'].pop()),
          ('infeasible_count',lambda p:p['kernel']['blocks'][0].__setitem__('count',5)),
          ('float_count',lambda p:p['kernel']['blocks'][0].__setitem__('count',2.0)),
          ('wrong_arithmetic',lambda p:p['kernel'].__setitem__('arithmetic','float32')),
          ('wrong_width',lambda p:p['kernel']['tensors'][0].__setitem__('bytes',8)),
          ('guard_operand_mismatch',lambda p:p['kernel']['events'][0].__setitem__('guard',1)),
          ('unconditional_sparse_use',lambda p:p['kernel']['events'][0].__setitem__('guard',-1)),
          ('output_range',lambda p:p['kernel']['events'][0].__setitem__('output',2)),
          ('unknown_format',lambda p:p['source']['scopes'][0].__setitem__('format','csr')),
          ('packed_dense_tensor',lambda p:p['source']['scopes'][1].__setitem__('format','bitmap')),
          ('parent_cycle',lambda p:p['source']['scopes'][0].__setitem__('parent',0)),
          ('extra_kernel_field',lambda p:p['kernel'].__setitem__('trusted',True)),
          ('extra_architecture_field',lambda p:p['architecture'].__setitem__('evictions',False)),
          ('unknown_top_field',lambda p:p.__setitem__('certificate',{})),
        ]
        for name,change in mutations:
            with self.subTest(name=name):self.assert_invalid_pair(change)
        self.assertEqual(len(mutations),26)

    def test_hierarchy_parent_admission(self):
        p=G.hierarchy(G.structured(1));p['source']['scopes'][0]['parent']=0
        with self.assertRaises(Invalid):validate_pair(p)
        p=G.hierarchy(G.structured(1));p['source']['scopes'][-2]['end']=1
        with self.assertRaises(Invalid):validate_pair(p)

    def test_signature_and_resident_codec(self):
        for fmt in ['dense','bitmap','coordinate']:
            for p in [G.structured(1,fmt=fmt),G.hierarchy(G.structured(1,fmt=fmt),fmt)]:
                k=p['kernel'];values=[[0,1,2**32-1,17],[3,5,7,11,13,17,19,23]]
                for x in masks(k):
                    outputs=[]
                    for which in ['source','target']:
                        c,terms=signature(k,p[which],len(p['architecture']['capacity']))
                        output,cost=execute_resident(p,which,x,values)
                        self.assertEqual(cost,traffic(p,which,x))
                        self.assertEqual(cost,[c[l]+sum(w for a,w in terms[l].items() if a&x) for l in range(len(c))])
                        self.assertEqual(output,execute(k,p[which],x,values));outputs.append(output)
                    self.assertEqual(*outputs)

    def test_cross_oracle_small_family_properties(self):
        """Cross-check four independent views over diverse bounded families."""
        cases=[
            G.structured(1,'free','dense'),
            G.structured(1,'nm','bitmap'),
            G.hierarchy(G.structured(1,'nm','coordinate'),'coordinate'),
            G.grid(2), G.cycle(3),
            G.format_change(4,'bitmap','coordinate',used=2,promise='nm'),
            G.cut_graph(3,[(0,1),(1,2),(0,2)]),
        ]
        for case,pair in enumerate(cases):
            with self.subTest(case=case):
                validate_pair(pair);xs=list(masks(pair['kernel']))
                for level in range(len(pair['architecture']['capacity'])):
                    c,terms=difference(pair,level)
                    observed=[]
                    for x in xs:
                        literal=traffic(pair,'target',x)[level]-traffic(pair,'source',x)[level]
                        self.assertEqual(eval_difference(c,terms,x),literal)
                        observed.append(literal)
                    self.assertEqual(Counter(pair['kernel']).square(c,terms),sum(z*z for z in observed))
                    cert=prove_upper(pair,level=level)
                    checked=check_upper(pair,cert,level,cert['bound'])
                    self.assertTrue(checked['accepted']);self.assertTrue(checked['exact'])
                    self.assertEqual(cert['bound'],max(observed))

    def test_packed_overfetch_and_hierarchy_levels(self):
        """Unused packed positions count only after a descendant triggers the tile."""
        pair=G.format_change(4,'bitmap','coordinate',used=2,promise='nm')
        c,terms=difference(pair)
        # 0b1100 activates only unused positions: neither compared tile is loaded.
        self.assertEqual(eval_difference(c,terms,0b1100),0)
        # 0b1001 activates a used guard and an overfetched packed position.
        x=0b1001
        self.assertEqual(eval_difference(c,terms,x),traffic(pair,'target',x)[0]-traffic(pair,'source',x)[0])
        hierarchical=G.hierarchy(G.structured(1,'nm','coordinate'),'bitmap')
        for level in range(2):
            c,terms=difference(hierarchical,level)
            for mask in masks(hierarchical['kernel']):
                self.assertEqual(eval_difference(c,terms,mask),
                    traffic(hierarchical,'target',mask)[level]-traffic(hierarchical,'source',mask)[level])

    def test_unconditional_events(self):
        k=G.kernel(2,[G.event(-1,2),G.event(0,0),G.event(1,1)],3,1)
        k['tensors'][0]['support']=[0,1,-1]
        s=G.mapping(k,[0,1,2],[[[0,1,2]],[[0],[1,2]]],('coordinate','dense'))
        t=G.mapping(k,[1,2,0],[[[0,1,2]],[[0,1,2]]],('bitmap','dense'))
        p=G.pair(k,s,t);c,terms=difference(p)
        for x in masks(k):
            self.assertEqual(eval_difference(c,terms,x),traffic(p,'target',x)[0]-traffic(p,'source',x)[0])
            a,ca=execute_resident(p,'source',x,[[4,0,9],[5]])
            b,cb=execute_resident(p,'target',x,[[4,0,9],[5]])
            self.assertEqual(a,b)

    def test_equality_requires_promise(self):
        p=G.structured(2);cert={'kind':'equal','level':0,'square_sum':0}
        self.assertTrue(check_equal(p,cert)['accepted'])
        p['kernel']['blocks']=[{'ids':list(range(8)),'count':4}]
        with self.assertRaises(Invalid):check_equal(p,cert)
        p=G.structured(1,'free')
        with self.assertRaises(Invalid):check_equal(p,cert)

    def test_exact_moment_and_witness(self):
        for p in [G.structured(2),G.grid(3),G.cycle(7),G.cut_graph(3,[(0,1),(1,2),(0,2)],'nm')]:
            c,t=difference(p);counter=Counter(p['kernel']);allm=list(masks(p['kernel']))
            self.assertEqual(counter.square(c,t),sum(eval_difference(c,t,x)**2 for x in allm))
            x=counter.witness(c,t)
            if x is not None:self.assertIn(x,allm);self.assertNotEqual(eval_difference(c,t,x),0)

    def test_zero_full_and_mixed_count_blocks(self):
        p=G.grid(2);p['kernel']['blocks']=[{'ids':[0],'count':0},{'ids':[1],'count':1},{'ids':[2,3],'count':None}]
        c,t=difference(p);counter=Counter(p['kernel']);xs=list(masks(p['kernel']))
        self.assertEqual(counter.avoid(0),4)
        self.assertEqual(counter.square(c,t),sum(eval_difference(c,t,x)**2 for x in xs))
        cert=prove_upper(p);self.assertTrue(check_upper(p,cert,0,cert['bound'])['exact'])

    def test_upper_certificate_mutations(self):
        p=G.grid(3);original=prove_upper(p);B=original['bound']
        self.assertTrue(check_upper(p,original,0,B)['exact'])
        def lower_initial(c):c['layers'][0][0][2]=-1
        def lower_final(c):c['layers'][-1][0][2]-=1
        def missing(c):c['layers'][2].pop()
        def duplicate(c):c['layers'][2].append(copy.deepcopy(c['layers'][2][0]))
        def bad_occupancy(c):c['layers'][0][0][0]=1
        def bad_count(c):c['layers'][0][0][1]=[0]
        def bad_witness(c):c['witness']=0
        def illegal_witness(c):c['witness']=1<<9
        changes=[('initial',lower_initial),('terminal_potential',lower_final),('missing_successor',missing),
                 ('duplicate_state',duplicate),('occupancy',bad_occupancy),('count_arity',bad_count),
                 ('nonattaining_witness',bad_witness),('illegal_witness',illegal_witness),
                 ('order',lambda c:c['order'].__setitem__(0,1)),
                 ('level',lambda c:c.__setitem__('level',True)),
                 ('bound',lambda c:c.__setitem__('bound',B-1)),
                 ('kind',lambda c:c.__setitem__('kind','equal')),
                 ('omit_layer',lambda c:c['layers'].pop()),
                 ('extra_field',lambda c:c.__setitem__('trusted',True))]
        for name,change in changes:
            with self.subTest(name=name):
                c=copy.deepcopy(original);change(c)
                with self.assertRaises((Invalid,AnalysisLimit)):check_upper(p,c,0,B)
        self.assertEqual(len(changes),14)

    def test_informational_statistics_not_trusted(self):
        p=G.grid(2);cert=prove_upper(p);cert['statistics']={'not_a_proof':-999999}
        self.assertTrue(check_upper(p,cert,0,cert['bound'])['accepted'])

    def test_valid_loose_upper_certificate(self):
        p=G.grid(2);cert=prove_upper(p);cert['bound']+=4;cert['witness']=None
        result=check_upper(p,cert,0,cert['bound']);self.assertTrue(result['accepted']);self.assertFalse(result['exact'])

    def test_guard_order_permutations(self):
        p=G.cut_graph(3,[(0,1),(1,2),(0,2)],'nm')
        for order in [list(range(12)),list(reversed(range(12))),[0,4,8,1,5,9,2,6,10,3,7,11]]:
            cert=prove_upper(p,order);self.assertEqual(cert['bound'],8)
            self.assertTrue(check_upper(p,cert,0,8)['accepted'])

    def test_limits_are_unresolved(self):
        p=G.grid(4);c,t=difference(p)
        with self.assertRaises(AnalysisLimit):Counter(p['kernel']).square(c,t,budget=Budget(operations=1))
        with self.assertRaises(AnalysisLimit):prove_upper(p,max_layer=1)
        with self.assertRaises(AnalysisLimit):prove_upper(p,max_total=1)
        with self.assertRaises(AnalysisLimit):list(masks(G.structured(8)['kernel']))

    def test_density_null_and_cycle_control(self):
        p=G.grid(4);c,t=difference(p);self.assertEqual(c,0);self.assertEqual(histogram(t),{})
        self.assertEqual(eval_difference(c,t,15),12)
        p=G.cycle(7);c,t=difference(p)
        self.assertEqual([x for x in masks(p['kernel']) if eval_difference(c,t,x)>0],[127])

    def test_merge_and_capacity_gap(self):
        p=G.grid(2);k=p['kernel'];a=copy.deepcopy(p['architecture']);m=p['source']
        # B row lifetimes abut; merging is legal and saves one repeated load.
        q=merge(k,a,m,4,5);pair=G.pair(k,m,q,a['capacity']);c,t=difference(pair)
        self.assertTrue(all(eval_difference(c,t,x)<=0 for x in masks(k)))
        # Retaining a B tile across a distinct B reservation requires 12 bytes.
        k=G.kernel(3,[G.event(i,i) for i in range(3)],3,1)
        m=G.mapping(k,[0,1,2],[[[0],[1],[2]],[[0],[1],[2]]]);p=G.pair(k,m,m,[8])
        with self.assertRaises(Invalid):merge(k,p['architecture'],m,3,5)

    def test_split_header_negative_control(self):
        p=G.format_change(4,'dense','dense');k=p['kernel'];a=p['architecture'];m=p['source']
        q=split(k,a,m,0,2);c,t=difference(G.pair(k,m,q,a['capacity']))
        self.assertTrue(all(eval_difference(c,t,x)<=0 for x in masks(k)))
        p=G.format_change(4,'coordinate','coordinate');k=p['kernel'];a=p['architecture'];m=p['source']
        with self.assertRaises(Invalid):split(k,a,m,0,2)
        a=copy.deepcopy(a);a['capacity'][0]+=8;q=split(k,a,m,0,2)
        c,t=difference(G.pair(k,m,q,a['capacity']));self.assertEqual(eval_difference(c,t,9),8)

    def test_format_rewrite_and_slot_interchange(self):
        p=G.structured(1);q=reencode(p['kernel'],p['architecture'],p['source'],0,'bitmap')
        c,t=difference(G.pair(p['kernel'],p['source'],q));self.assertTrue(all(eval_difference(c,t,x)<=0 for x in masks(p['kernel'])))
        edges=[(0,1),(0,2),(1,2)];p=G.cut_graph(3,edges);k=p['kernel'];a=p['architecture']
        q=apply_trace(k,a,p['source'],[{'rule':'interchange','position':4*j+1,'slot_operands':[1]} for j in range(3)])
        c,t=difference(G.pair(k,q,p['target'],[8]));self.assertEqual(Counter(k).square(c,t),0)
        p2=G.pair(k,p['source'],q,[8]);c,t=difference(p2)
        for x in masks(k):self.assertEqual(eval_difference(c,t,x),4*sum(((x>>u)^(x>>v))&1 for u,v in edges))

        # The thresholded reduction adds an offset unit.  Edge gadgets are
        # reached by interchanges; the offset target additionally merges its
        # two adjacent B residencies.  Check the complete local trace rather
        # than conflating it with the cut_graph-only interchange experiment.
        threshold=G.cut_threshold(3,[(0,1),(1,2)],2);k=threshold['kernel'];a=threshold['architecture']
        trace=[
            {'rule':'interchange','position':1,'slot_operands':[1]},
            {'rule':'interchange','position':5,'slot_operands':[1]},
            {'rule':'merge','left':14,'right':15},
        ]
        q=threshold['source'];scope_counts=[len(q['scopes'])];peak_payload=[]
        for step in trace:
            q=apply_trace(k,a,q,[step]);scope_counts.append(len(q['scopes']))
            admitted=validate_pair({'kernel':k,'architecture':a,'source':threshold['source'],'target':q})
            peak_payload.append(admitted['target']['peak_payload_bytes'][0])
        self.assertEqual(scope_counts,[16,16,16,15])
        self.assertEqual(peak_payload,[8,8,8])
        self.assertEqual(q,threshold['target'])

    def test_fixed_zero_maxcut_reduction(self):
        # Exhaust every simple graph through four vertices and every nontrivial
        # Max-Cut threshold.  The literal traffic delta must be
        # 4*(cut-(L-1)), so the fixed request delta<=0 is true iff maxcut<L.
        for n in range(2,5):
            possible=list(itertools.combinations(range(n),2))
            for code in range(1,1<<len(possible)):
                edges=[e for i,e in enumerate(possible) if code>>i&1]
                maxcut=max(sum(((x>>u)^(x>>v))&1 for u,v in edges) for x in range(1<<n))
                for threshold in range(1,len(edges)+1):
                    p=G.cut_threshold(n,edges,threshold);c,t=difference(p)
                    values=[]
                    for x in masks(p['kernel']):
                        cut=sum(((x>>u)^(x>>v))&1 for u,v in edges)
                        z=traffic(p,'target',x)[0]-traffic(p,'source',x)[0]
                        self.assertEqual(z,4*(cut-(threshold-1)))
                        self.assertEqual(z,eval_difference(c,t,x));values.append(z)
                    self.assertEqual(max(values),4*(maxcut-(threshold-1)))
                    self.assertEqual(all(z<=0 for z in values),maxcut<threshold)
                    self.assertEqual(p['architecture']['capacity'],[8])
        # Check that the 2:4 lifting preserves the same projected threshold.
        edges=[(0,1),(0,2),(1,2)]
        for threshold in range(1,4):
            p=G.cut_threshold(3,edges,threshold,'nm');c,t=difference(p)
            for x in masks(p['kernel']):
                cut=sum((((x>>(4*u))&1)^((x>>(4*v))&1)) for u,v in edges)
                z=traffic(p,'target',x)[0]-traffic(p,'source',x)[0]
                self.assertEqual(z,4*(cut-(threshold-1)))
                self.assertEqual(z,eval_difference(c,t,x))

    def test_shipped_certificate_example(self):
        pair=json.loads((ROOT/'examples'/'structured.json').read_text())
        certificate=json.loads((ROOT/'examples'/'structured-zero-bound-certificate.json').read_text())
        checked=check_upper(pair,certificate,0,0)
        self.assertTrue(checked['accepted']);self.assertTrue(checked['exact'])
        self.assertEqual(certificate['statistics']['total_states'],9)
        with self.assertRaises(AnalysisLimit):check_upper(pair,certificate,0,0,max_layer=1)
        self.assertTrue(check_upper(pair,certificate,0,0,max_layer=3)['accepted'])

    def test_signed_64bit_certificate_boundary(self):
        pair=G.grid(2);certificate=prove_upper(pair);bound=certificate['bound']
        with self.assertRaises(Invalid):check_upper(pair,certificate,0,2**63)
        broken=copy.deepcopy(certificate);broken['layers'][0][0][2]=2**63
        with self.assertRaises(Invalid):check_upper(pair,broken,0,bound)


    def test_rewrite_trace_validation(self):
        p=G.grid(2);k=p['kernel'];a=p['architecture'];m=p['source']
        self.assertEqual(apply_trace(k,a,m,[]),m)
        merged=apply_trace(k,a,m,[{'rule':'merge','left':4,'right':5}])
        validate_pair(G.pair(k,m,merged,a['capacity']))

        p=G.format_change(4,'dense','dense');k=p['kernel'];a=p['architecture'];m=p['source']
        split_map=apply_trace(k,a,m,[{'rule':'split','scope':0,'cut':2}])
        validate_pair(G.pair(k,m,split_map,a['capacity']))
        encoded=apply_trace(k,a,m,[{'rule':'reencode','scope':0,'format':'bitmap'}])
        validate_pair(G.pair(k,m,encoded,a['capacity']))

        malformed=[None,[{}],[{'rule':'unknown'}],[{'rule':'merge','left':0,'right':1,'extra':True}],[{}]*1025]
        for trace in malformed:
            with self.subTest(trace_type=type(trace).__name__,length=len(trace) if isinstance(trace,list) else -1):
                with self.assertRaises(Invalid):apply_trace(k,a,m,trace)

        hierarchical=G.hierarchy(G.structured(1));k=hierarchical['kernel'];a=hierarchical['architecture'];m=hierarchical['source']
        root=next(i for i,scope in enumerate(m['scopes']) if scope['level']==0)
        with self.assertRaises(Invalid):
            apply_trace(k,a,m,[{'rule':'reencode','scope':root,'format':'dense'}])
        with self.assertRaises(Invalid):
            apply_trace(k,a,m,[{'rule':'interchange','position':0,'slot_operands':[0,0]}])

    def test_cli_roundtrip(self):
        pair=ROOT/'examples'/'structured.json'
        def run(*arguments,expected=0):
            command=[sys.executable]
            if sys.flags.optimize:
                command.append('-O')
            command.extend(['-m','dataflow',*map(str,arguments)])
            environment=dict(os.environ,PYTHONPATH=str(ROOT/'src'),PYTHONDONTWRITEBYTECODE='1')
            result=subprocess.run(command,cwd=ROOT,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            self.assertEqual(result.returncode,expected,msg=result.stdout+'\n'+result.stderr)
            return json.loads(result.stdout.strip().splitlines()[-1])
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);equal_path=directory/'equal.json';upper_path=directory/'upper.json'
            self.assertIn('admitted',run('validate',pair))
            self.assertTrue(run('equal',pair,'--output',equal_path)['accepted'])
            self.assertTrue(run('check-equal',pair,'--certificate',equal_path)['accepted'])
            upper=run('upper',pair,'--output',upper_path)
            certificate=json.loads(upper_path.read_text())
            self.assertTrue(upper['accepted']);self.assertEqual(upper['bound'],certificate['bound'])
            self.assertTrue(run('check-upper',pair,'--certificate',upper_path,'--bound',certificate['bound'])['accepted'])
            trace=run('trace',pair,'--mask',3)
            self.assertEqual(set(trace),{'source','target'})
            rejected=run('check-upper',pair,'--certificate',upper_path,expected=1)
            self.assertEqual(rejected['status'],'rejected')

            shipped=ROOT/'examples'/'structured-zero-bound-certificate.json'
            limited=run('check-upper',pair,'--certificate',shipped,'--bound',0,'--max-layer',1,expected=2)
            self.assertEqual(limited['status'],'unresolved')
            self.assertIn('layer state limit',limited['reason'])
            accepted=run('check-upper',pair,'--certificate',shipped,'--bound',0,'--max-layer',3)
            self.assertTrue(accepted['accepted'])
            damaged=json.loads(shipped.read_text());damaged['layers'][0][0][2]=1
            damaged_path=directory/'damaged-upper.json';damaged_path.write_text(json.dumps(damaged))
            invalid=run('check-upper',pair,'--certificate',damaged_path,'--bound',0,'--max-layer',3,expected=1)
            self.assertEqual(invalid['status'],'rejected')

    def test_json_duplicate_and_publication(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json';p.write_text('{"a":1,"a":2}')
            with self.assertRaises(Invalid):read_json(str(p))
            p=Path(d)/'proof.json';save_json(str(p),{'value':1})
            with self.assertRaises(FileExistsError):save_json(str(p),{'value':2})
            self.assertEqual(read_json(str(p)),{'value':1})
            self.assertEqual(sorted(x.name for x in Path(d).iterdir()),['input.json','proof.json'])

if __name__=='__main__':unittest.main(verbosity=2)
