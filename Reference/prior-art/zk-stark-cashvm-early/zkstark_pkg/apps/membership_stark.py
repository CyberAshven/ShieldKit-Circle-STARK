# Hidden-path Merkle membership + nullifier STARK (the mixer privacy core).
# Proves, in zero knowledge: "I know (secret, nullifier) and a Merkle authentication
# path of depth D such that leaf = Hh(secret+nullifier) hashes up to the PUBLIC root,
# and nullifierHash = Hh(nullifier+DOM)" -- WITHOUT revealing secret, nullifier, or the
# path. Reference-grade: real commit/FRI/Fiat-Shamir/grind/ZK-mask, low-degree AIR.
# NOT audited, params not production, soundness only empirically fuzzed below.
import os, json, hashlib, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stark import (P, add, sub, mul, inv, neg, G, root, interp, p_eval, p_mul, p_add,
                   Hf, enc, merkle, m_root, m_path, m_verify, FS, grind)

# ---- reference algebraic hash over Goldilocks: Hh(y)=perm(y); H2(a,b)=perm(a+b) ----
R_ROUNDS = 6
RC = [int.from_bytes(hashlib.sha256(b"memb-rc-%d" % i).digest()[:8], "little") % P
      for i in range(R_ROUNDS)]
DOM = 0x6e756c6c  # "null" domain tag for the nullifier-hash sub-computation
def perm(y):
    y %= P
    for r in range(R_ROUNDS):
        u = (y + RC[r]) % P
        y = pow(u, 7, P)
    return y
def H2(a, b):   # 2:1 compression (symmetric: order-free, so no path direction bit)
    return perm((a + b) % P)

# ---- trace layout -------------------------------------------------------------
# columns: st, u2,u4,u6 (round aux), nu,sec (held witness), inj (per-row sibling)
COLS = ["st", "u2", "u4", "u6", "nu", "inj"]   # secret folded into inj at the leaf row
def build_trace(secret, nullifier, siblings):
    D = len(siblings)
    rows = []   # each row i defines transition to i+1; we record type + data
    st = [0]    # st[0]=0
    types = []  # per transition-row: ('leaf'|'level'|'null'|'round'|'pad')
    injv = []   # inj value used at this row (siblings); else 0
    def round_step(cur):
        u = (cur + RC[round_step.r]) % P
        nx = pow(u, 7, P)
        round_step.r += 1
        return u, nx
    # leaf: inject secret (via inj) + nullifier (held), then R rounds -> digest0
    types.append("leaf"); injv.append(secret % P); st.append((secret + nullifier) % P)
    round_step.r = 0
    for _ in range(R_ROUNDS):
        u, nx = round_step(st[-1]); types.append("round"); injv.append(0); st.append(nx)
    # D levels
    for j in range(D):
        types.append("level"); injv.append(siblings[j] % P); st.append((st[-1] + siblings[j]) % P)
        round_step.r = 0
        for _ in range(R_ROUNDS):
            u, nx = round_step(st[-1]); types.append("round"); injv.append(0); st.append(nx)
    root_row = len(st) - 1                      # st[root_row] == public root
    # nullifier hash: set st = nu+DOM (absolute), then R rounds
    types.append("null"); injv.append(0); st.append((nullifier + DOM) % P)
    round_step.r = 0
    for _ in range(R_ROUNDS):
        u, nx = round_step(st[-1]); types.append("round"); injv.append(0); st.append(nx)
    null_row = len(st) - 1
    # pad to power of two with copy rows
    T = 1
    while T < len(st): T <<= 1
    while len(st) < T:
        types.append("pad"); injv.append(0); st.append(st[-1])
    # build columns
    n = len(st)
    col = {c: [0] * n for c in COLS}
    col["st"] = st[:]
    col["nu"] = [nullifier % P] * n
    # aux + inj per transition row (row i feeds transition to i+1)
    for i in range(n - 1):
        t = types[i]
        if t == "round":
            u = (st[i] + RC[(_round_index(types, i))]) % P
            u2 = mul(u, u); u4 = mul(u2, u2); u6 = mul(u4, u2)
            col["u2"][i] = u2; col["u4"][i] = u4; col["u6"][i] = u6
        col["inj"][i] = injv[i]
    return col, n, root_row, null_row, types

def _round_index(types, i):
    # round constant index = position within current run of 'round's
    k = 0
    while i - 1 - k >= 0 and types[i - 1 - k] == "round":
        k += 1
    return k

# ---- public per-row selector + rc polynomials (known to verifier) -------------
def public_layout(types, n):
    is_round = [0]*n; sel_leaf=[0]*n; sel_level=[0]*n; sel_null=[0]*n; sel_pad=[0]*n; rc=[0]*n
    for i in range(n-1):
        t = types[i]
        if t=="round":
            is_round[i]=1; rc[i]=RC[_round_index(types,i)]
        elif t=="leaf": sel_leaf[i]=1
        elif t=="level": sel_level[i]=1
        elif t=="null": sel_null[i]=1
        elif t=="pad": sel_pad[i]=1
    return is_round, sel_leaf, sel_level, sel_null, sel_pad, rc

# ---- STARK parameters ---------------------------------------------------------
mask_deg = 20
blowup   = 8
def setup(T, blowup=8):
    B = 128
    N = B * blowup
    while N % T != 0: N += B*blowup  # ensure T | N
    oT = root(T); oN = root(N); off = G
    Hd = [pow(oT,i,P) for i in range(T)]
    Dd = [mul(off, pow(oN,i,P)) for i in range(N)]
    return B,N,oT,oN,off,Hd,Dd,Hd[T-1]

# constraint set: each is (kind, fn). kind 'T' transition (vanish rows<last), or ('B',row).
def constraints(rc_p, isr_p, sl_p, slv_p, sn_p, sp_p, root_val, nh_val, root_row, null_row, oT, T):
    def at(poly, x): return p_eval(poly, x)
    cons = []
    # transition constraints use current(c) and next(c2) column dicts + x
    def c_u2(c,c2,x):
        u = add(c["st"], at(rc_p,x)); return mul(at(isr_p,x), sub(c["u2"], mul(u,u)))
    def c_u4(c,c2,x): return mul(at(isr_p,x), sub(c["u4"], mul(c["u2"],c["u2"])))
    def c_u6(c,c2,x): return mul(at(isr_p,x), sub(c["u6"], mul(c["u4"],c["u2"])))
    def c_st(c,c2,x):
        u = add(c["st"], at(rc_p,x))
        rnd = mul(at(isr_p,x), mul(c["u6"], u))
        leaf= mul(at(sl_p,x),  add(c["st"], add(c["inj"], c["nu"])))
        lvl = mul(at(slv_p,x), add(c["st"], c["inj"]))
        nul = mul(at(sn_p,x),  add(c["nu"], DOM))
        pad = mul(at(sp_p,x),  c["st"])
        return sub(c2["st"], add(add(add(rnd,leaf),add(lvl,nul)),pad))
    def c_nu(c,c2,x):  return sub(c2["nu"], c["nu"])
    for fn in (c_u2,c_u4,c_u6,c_st,c_nu): cons.append(("T", fn))
    # boundary
    cons.append((("B",0),       lambda c,c2,x: sub(c["st"], 0)))
    cons.append((("B",root_row),lambda c,c2,x: sub(c["st"], root_val)))
    cons.append((("B",null_row),lambda c,c2,x: sub(c["st"], nh_val)))
    return cons

def _rowvals(col, i):  return {c: col[c][i] for c in COLS}

def air_check(col, n, root_row, null_row, types):
    isr,sl,slv,sn,sp,rc = public_layout(types, n)
    oT = root(n)
    # check on H directly (row form)
    ok = True
    for i in range(n-1):
        c = _rowvals(col,i); c2=_rowvals(col,i+1)
        u = add(c["st"], rc[i])
        if isr[i]:
            if c["u2"]!=mul(u,u) or c["u4"]!=mul(c["u2"],c["u2"]) or c["u6"]!=mul(c["u4"],c["u2"]): ok=False
        rnd = isr[i]*mul(c["u6"],u) % P
        nxt = (isr[i]*mul(c["u6"],u) + sl[i]*((c["st"]+c["inj"]+c["nu"])%P) +
               slv[i]*((c["st"]+c["inj"])%P) + sn[i]*((c["nu"]+DOM)%P) + sp[i]*c["st"]) % P
        if c2["st"]!=nxt: ok=False; 
        if c2["nu"]!=c["nu"]: ok=False
    return ok

# ---- layout-only rebuild (verifier knows this from public depth D) ------------
def build_layout(D):
    types = []
    types.append("leaf"); types += ["round"]*R_ROUNDS
    for _ in range(D):
        types.append("level"); types += ["round"]*R_ROUNDS
    root_row = len(types)            # index of digest after appends == current st length
    types.append("null"); types += ["round"]*R_ROUNDS
    null_row = len(types)
    pre = null_row + 1
    T = 1
    while T < pre: T <<= 1
    types += ["pad"]*(T - pre)
    return types, T, root_row, null_row

def _interp_pub(vals, Hd):  return interp(Hd, vals)
def leaf_multi(vals, salt): return Hf(salt + b"".join(enc(v) for v in vals))
queries = 16            # proof ~64.7KB ; single-input loop tx ~74.3KB (both <=90KB)
grind_bits = 42         # DEPLOY value (PoW; trivial on mining hardware). tests use 8.
#   conjectured security ~= queries*log2(blowup) + grind_bits
#   q16,blowup8,grind42 ~= 90 bits. size is grind-INDEPENDENT (nonce is 8 bytes).

def prove(secret, nullifier, siblings, grind_b=grind_bits, blowup=blowup, n_queries=queries):
    col, T, root_row, null_row, types = build_trace(secret, nullifier, siblings)
    root_val = col["st"][root_row]; nh_val = col["st"][null_row]
    B,N,oT,oN,off,Hd,Dd,last = setup(T, blowup)
    isr,sl,slv,sn,sp,rc = public_layout(types, T)
    rc_p=_interp_pub(rc,Hd); isr_p=_interp_pub(isr,Hd); sl_p=_interp_pub(sl,Hd)
    slv_p=_interp_pub(slv,Hd); sn_p=_interp_pub(sn,Hd); sp_p=_interp_pub(sp,Hd)
    ZHpoly=[neg(1)]+[0]*(T-1)+[1]
    # mask each column (ZK) and evaluate on D
    colvals={}
    for c in COLS:
        poly=interp(Hd, col[c])
        Rr=[int.from_bytes(os.urandom(8),'little')%P for _ in range(mask_deg)]
        masked=p_add(poly, p_mul(ZHpoly, Rr))
        colvals[c]=[p_eval(masked,x) for x in Dd]
    salts=[os.urandom(16) for _ in range(N)]
    leaves=[leaf_multi([colvals[c][i] for c in COLS], salts[i]) for i in range(N)]
    tree=merkle(leaves)
    fs=FS(); fs.absorb(m_root(tree)); fs.absorb_int(root_val); fs.absorb_int(nh_val)
    cons=constraints(rc_p,isr_p,sl_p,slv_p,sn_p,sp_p,root_val,nh_val,root_row,null_row,oT,T)
    alphas=[fs.challenge() for _ in cons]
    shift=N//T
    comp=[0]*N
    for i,x in enumerate(Dd):
        cur={c:colvals[c][i] for c in COLS}; nxt={c:colvals[c][(i+shift)%N] for c in COLS}
        ZHx=sub(pow(x,T,P),1)
        acc=0
        for a,(kind,fn) in zip(alphas,cons):
            v=fn(cur,nxt,x)
            if kind=="T": q=mul(mul(v,sub(x,last)),inv(ZHx))
            else: q=mul(v, inv(sub(x, Hd[kind[1]])))
            acc=add(acc, mul(a,q))
        comp[i]=acc
    # FRI (same engine as stark.py)
    fri_layers=[]; fri_trees=[]; vals=comp[:]; dom=Dd[:]; betas=[]
    fs.absorb(b"fri")
    while True:
        tr=merkle([leaf_multi([vals[i]], b"\x00"*16) for i in range(len(vals))])
        fri_layers.append(vals); fri_trees.append(tr); fs.absorb(m_root(tr))
        if len(vals)<=8: break
        beta=fs.challenge(); betas.append(beta); half=len(vals)//2; nv=[0]*half
        for i in range(half):
            x=dom[i]; fp=vals[i]; fn_=vals[i+half]
            nv[i]=add(mul(add(fp,fn_),inv(2)), mul(beta, mul(sub(fp,fn_), inv(mul(2,x)))))
        vals=nv; dom=[mul(d,d) for d in dom[:half]]
    final=fri_layers[-1]
    nonce=grind(fs.s, grind_b); fs.absorb(nonce)
    idxs=[fs.challenge_idx(N) for _ in range(n_queries)]
    Q=[]
    for k in idxs:
        kn=(k+shift)%N
        op={'k':k,
            'ck':{c:colvals[c][k] for c in COLS},'sk':salts[k].hex(),'pk':[(s.hex(),b) for s,b in m_path(tree,k)],
            'cn':{c:colvals[c][kn] for c in COLS},'sn':salts[kn].hex(),'pn':[(s.hex(),b) for s,b in m_path(tree,kn)],
            'fri':[]}
        ci=k
        for li in range(len(fri_layers)-1):
            half=len(fri_layers[li])//2; i=ci%half
            op['fri'].append({'v':fri_layers[li][i],'vp':[(s.hex(),b) for s,b in m_path(fri_trees[li],i)],
                              'w':fri_layers[li][i+half],'wp':[(s.hex(),b) for s,b in m_path(fri_trees[li],i+half)]})
            ci=i
        Q.append(op)
    return {'D':len(siblings),'root':root_val,'nh':nh_val,'tp_root':m_root(tree).hex(),
            'fri_roots':[m_root(t).hex() for t in fri_trees],'final':final,'betas':betas,
            'nonce':nonce.hex(),'queries':Q,'grind_b':grind_b,'blowup':blowup,'nq':len(Q)}

def verify(proof):
    D=proof['D']; root_val=proof['root']; nh_val=proof['nh']
    types,T,root_row,null_row=build_layout(D)
    B,N,oT,oN,off,Hd,Dd,last=setup(T, proof.get('blowup',8))
    isr,sl,slv,sn,sp,rc=public_layout(types,T)
    rc_p=_interp_pub(rc,Hd); isr_p=_interp_pub(isr,Hd); sl_p=_interp_pub(sl,Hd)
    slv_p=_interp_pub(slv,Hd); sn_p=_interp_pub(sn,Hd); sp_p=_interp_pub(sp,Hd)
    cons=constraints(rc_p,isr_p,sl_p,slv_p,sn_p,sp_p,root_val,nh_val,root_row,null_row,oT,T)
    tp_root=bytes.fromhex(proof['tp_root']); fri_roots=[bytes.fromhex(r) for r in proof['fri_roots']]
    fs=FS(); fs.absorb(tp_root); fs.absorb_int(root_val); fs.absorb_int(nh_val)
    alphas=[fs.challenge() for _ in cons]
    fs.absorb(b"fri"); betas=[]; sizes=[]; size=N; ri=0
    while True:
        fs.absorb(fri_roots[ri]); sizes.append(size); ri+=1
        if size<=8: break
        betas.append(fs.challenge()); size//=2
    if betas!=proof['betas']: return False,"beta mismatch"
    nonce=bytes.fromhex(proof['nonce'])
    if int.from_bytes(Hf(fs.s+nonce)[:8],'little')>=(1<<(64-proof['grind_b'])): return False,"grind"
    fs.absorb(nonce)
    nq=proof.get('nq',queries)
    idxs=[fs.challenge_idx(N) for _ in range(nq)]
    if [q['k'] for q in proof['queries']]!=idxs: return False,"idx mismatch"
    final=proof['final']; shift=N//T
    for q in proof['queries']:
        k=q['k']; x=Dd[k]; kn=(k+shift)%N
        if not m_verify(tp_root, leaf_multi([q['ck'][c] for c in COLS], bytes.fromhex(q['sk'])), k,
                        [(bytes.fromhex(s),b) for s,b in q['pk']]): return False,"col path k"
        if not m_verify(tp_root, leaf_multi([q['cn'][c] for c in COLS], bytes.fromhex(q['sn'])), kn,
                        [(bytes.fromhex(s),b) for s,b in q['pn']]): return False,"col path kn"
        cur=q['ck']; nxt=q['cn']; ZHx=sub(pow(x,T,P),1); acc=0
        for a,(kind,fn) in zip(alphas,cons):
            v=fn(cur,nxt,x)
            if kind=="T": qd=mul(mul(v,sub(x,last)),inv(ZHx))
            else: qd=mul(v, inv(sub(x,Hd[kind[1]])))
            acc=add(acc, mul(a,qd))
        comp_x=acc
        ci=k
        for li,fl in enumerate(q['fri']):
            half=sizes[li]//2; i=ci%half
            if not m_verify(fri_roots[li], leaf_multi([fl['v']], b"\x00"*16), i,
                            [(bytes.fromhex(s),b) for s,b in fl['vp']]): return False,f"fri{li} v"
            if not m_verify(fri_roots[li], leaf_multi([fl['w']], b"\x00"*16), i+half,
                            [(bytes.fromhex(s),b) for s,b in fl['wp']]): return False,f"fri{li} w"
            if li==0:
                tgt=fl['w'] if k>=half else fl['v']
                if tgt!=comp_x: return False,"comp != fri0"
            xpos=pow(mul(off,pow(oN,i,P)),2**li,P); beta=betas[li]
            folded=add(mul(add(fl['v'],fl['w']),inv(2)), mul(beta, mul(sub(fl['v'],fl['w']), inv(mul(2,xpos)))))
            if li+1<len(q['fri']):
                nh2=sizes[li+1]//2; tgt=q['fri'][li+1]['w'] if (i>=nh2) else q['fri'][li+1]['v']
                if folded!=tgt: return False,f"fold L{li}"
            else:
                if folded!=final[i%len(final)]: return False,"fri final"
            ci=i
    return True,"ok"
