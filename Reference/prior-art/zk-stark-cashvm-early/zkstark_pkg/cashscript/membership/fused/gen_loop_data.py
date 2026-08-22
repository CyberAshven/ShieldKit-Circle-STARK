# Export per-query (k, x) pairs from a real membership proof for fused_loop.mjs.
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'apps'))
import membership_stark as M
p = M.prove(111, 222, [10,20,30,40], grind_b=8)
B,N,oT,oN,off,Hd,Dd,last = M.setup(64, p['blowup'])
pairs = [(q['k'], Dd[q['k']]) for q in p['queries']]
json.dump(dict(P=str(M.P), omegaN=str(oN%M.P), offset=str(off%M.P), N=N,
               pairs=[[k, str(x)] for k,x in pairs]), open('/tmp/loop.json','w'))
print('exported', len(pairs), 'pairs to /tmp/loop.json ; run: node fused_loop.mjs')
