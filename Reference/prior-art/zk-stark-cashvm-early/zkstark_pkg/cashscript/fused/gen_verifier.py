import json, sys
d=json.load(open('verifier_inputs.json'))
P=int(d['P']); N=d['N']; omega=int(d['omegaN']); offset=int(d['offset'])
inv2=int.from_bytes(bytes.fromhex(d['inv2']),'little'); C=int(d['C']); out=int(d['out']); last=int(d['last'])
k0=d['k0']; half0=d['half0']; nB=d['nBetas']
tp=int(d['tp']); tpn=int(d['tpn']); a1=int(d['a1']); a2=int(d['a2'])
invXn1=int(d['invXn1']); invXlast=int(d['invXlast']); v0=int(d['v0']); w0=int(d['w0'])
def ch(h): b=bytes.fromhex(h); return [int.from_bytes(b[i:i+8],'little') for i in range(0,len(b),8)]
vs=ch(d['vs']); ws=ch(d['ws']); betas=ch(d['betas']); inv2xs=ch(d['inv2xpos'])
tp_root=d['tp_root']; tp_leaf=d['tp_leaf']; tpn_leaf=d['tpn_leaf']
tp_path=d['tp_path']; tpn_path=d['tpn_path']; final_hex=d['final']
# tamper hook
mode=sys.argv[1] if len(sys.argv)>1 else ''
if mode=='tp': tp^=1
elif mode=='beta': betas[0]^=1
elif mode=='root': b=bytearray(bytes.fromhex(tp_root)); b[0]^=1; tp_root=b.hex()
elif mode=='a1': a1^=1
elif mode=='tppath': s,bt=tp_path[0]; bb=bytearray(bytes.fromhex(s)); bb[0]^=1; tp_path=[(bb.hex(),bt)]+tp_path[1:]

Ph='<0x01000000ffffffff00>'; MOD=Ph+' OP_MOD'
def modexp():
    return ('OP_TOALTSTACK OP_TOALTSTACK OP_1 OP_FROMALTSTACK OP_FROMALTSTACK '
            'OP_BEGIN OP_DUP OP_2 OP_DIV OP_TOALTSTACK OP_2 OP_MOD '
            f'OP_IF OP_DUP OP_ROT OP_MUL {MOD} OP_SWAP OP_ENDIF '
            f'OP_DUP OP_MUL {MOD} OP_FROMALTSTACK OP_DUP OP_0 OP_NUMEQUAL OP_UNTIL OP_2DROP')
def trace(leaf, path, root):
    t=[f'<0x{leaf}>','OP_SHA256']
    for sib,bit in path:
        if bit==0: t+=[f'<0x{sib}>','OP_CAT','OP_SHA256']
        else: t+=[f'<0x{sib}>','OP_SWAP','OP_CAT','OP_SHA256']
    t+=[f'<0x{root}>','OP_EQUALVERIFY']; return ' '.join(t)
def composition():
    TARGET = v0 if k0<half0 else w0
    t=[f'<{omega}>',f'<{k0}>',modexp(),f'<{offset}>','OP_MUL',MOD,'OP_DUP']      # [x x]
    for _ in range(4): t+=['OP_DUP','OP_MUL',MOD]                                  # x^16 -> [x x16]
    t+=['OP_1SUB',f'<{invXn1}>','OP_MUL',MOD,'OP_1','OP_NUMEQUALVERIFY']           # invXn1 check -> [x]
    t+=[f'<{last}>','OP_SUB',Ph,'OP_ADD',MOD]                                      # xml -> [xml]
    t+=['OP_DUP',f'<{invXlast}>','OP_MUL',MOD,'OP_1','OP_NUMEQUALVERIFY']          # invXlast check -> [xml]
    t+=[f'<{tpn}>',f'<{tp}>','OP_DUP','OP_MUL',MOD,'OP_SUB',f'<{C}>','OP_SUB',Ph,'OP_ADD',Ph,'OP_ADD',MOD]  # Pt -> [xml Pt]
    t+=['OP_OVER','OP_MUL',MOD,f'<{invXn1}>','OP_MUL',MOD]                         # Qt -> [xml Qt]
    t+=[f'<{tp}>',f'<{out}>','OP_SUB',Ph,'OP_ADD',MOD,f'<{invXlast}>','OP_MUL',MOD] # Qb -> [xml Qt Qb]
    t+=[f'<{a2}>','OP_MUL',MOD,'OP_SWAP',f'<{a1}>','OP_MUL',MOD,'OP_ADD',MOD]      # comp -> [xml comp]
    t+=[f'<{TARGET}>','OP_NUMEQUALVERIFY','OP_DROP']                               # []
    return ' '.join(t)
def layer(li):
    half=N//(2**(li+1)); V=vs[li]; W=ws[li]; B=betas[li]; IX=inv2xs[li]
    t=['OP_2','OP_ROLL',f'<{half}>','OP_MOD']
    if li>0:
        t+=['OP_OVER',f'<{half}>','OP_LESSTHAN','OP_IF',f'<{V}>','OP_ELSE',f'<{W}>','OP_ENDIF',
            'OP_3','OP_ROLL','OP_NUMEQUALVERIFY','OP_SWAP','OP_DROP']
    else:
        t+=['OP_SWAP','OP_DROP','OP_SWAP','OP_DROP']
    t+=['OP_DUP',f'<{omega}>','OP_SWAP',modexp(),f'<{offset}>','OP_MUL',MOD]
    for _ in range(li): t+=['OP_DUP','OP_MUL',MOD]
    t+=['OP_2','OP_MUL',MOD,f'<{IX}>','OP_MUL',MOD,'OP_1','OP_NUMEQUALVERIFY']
    t+=[f'<{V}>',f'<{W}>','OP_ADD',MOD,f'<{inv2}>','OP_MUL',MOD]
    t+=[f'<{V}>',f'<{W}>','OP_SUB',Ph,'OP_ADD',MOD]
    t+=[f'<{IX}>','OP_MUL',MOD,f'<{B}>','OP_MUL',MOD]
    t+=['OP_ADD',MOD,'OP_OVER']
    return ' '.join(t)
prog=['OP_DROP']                      # drop the unlocking budget blob
prog.append(trace(tp_leaf, tp_path, tp_root))
prog.append(trace(tpn_leaf, tpn_path, tp_root))
prog.append(composition())
prog.append(f'<0x{final_hex}> <{k0}> OP_0 OP_0')
for li in range(nB): prog.append(layer(li))
prog.append('OP_8 OP_MUL OP_3 OP_ROLL OP_SWAP OP_SPLIT OP_NIP OP_8 OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM OP_NUMEQUALVERIFY OP_DROP OP_1')
open('verifier.asm','w').write('\n'.join(prog))
print('generated verifier.asm', '(tamper='+mode+')' if mode else '', 'tokens~', sum(len(x.split()) for x in prog))
