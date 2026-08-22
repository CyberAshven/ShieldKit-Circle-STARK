import json
d=json.load(open('fold_inputs.json'))
P=int(d['P']); N=d['N']; k0=d['k0']; nB=d['nBetas']
omega=int(d['omegaN']); offset=int(d['offset']); inv2=int.from_bytes(bytes.fromhex(d['inv2']),'little')
def chunks(h): b=bytes.fromhex(h); return [int.from_bytes(b[i:i+8],'little') for i in range(0,len(b),8)]
vs=chunks(d['vs']); ws=chunks(d['ws']); betas=chunks(d['betas']); inv2xs=chunks(d['inv2xpos'])
final_hex=d['final']  # raw concatenated 8-byte LE chunks
Ph='<0x01000000ffffffff00>'
MOD=f'{Ph} OP_MOD'
def modexp():  # [base exp] -> [result]
    return ('OP_TOALTSTACK OP_TOALTSTACK OP_1 OP_FROMALTSTACK OP_FROMALTSTACK '
            'OP_BEGIN OP_DUP OP_2 OP_DIV OP_TOALTSTACK OP_2 OP_MOD '
            f'OP_IF OP_DUP OP_ROT OP_MUL {MOD} OP_SWAP OP_ENDIF '
            f'OP_DUP OP_MUL {MOD} OP_FROMALTSTACK OP_DUP OP_0 OP_NUMEQUAL OP_UNTIL OP_2DROP')
def layer(li):
    half=N//(2**(li+1)); V=vs[li]; W=ws[li]; B=betas[li]; IX=inv2xs[li]
    t=[]
    # precondition [FINAL ci pf pi]; compute i_idx = ci % half
    t+=['OP_2','OP_ROLL',f'<{half}>','OP_MOD']      # [FINAL pf pi i_idx]
    if li>0:
        t+=['OP_OVER',f'<{half}>','OP_LESSTHAN','OP_IF',f'<{V}>','OP_ELSE',f'<{W}>','OP_ENDIF']  # [..pf pi i_idx sel]
        t+=['OP_3','OP_ROLL','OP_NUMEQUALVERIFY']   # pf==sel -> [FINAL pi i_idx]
        t+=['OP_SWAP','OP_DROP']                     # drop pi -> [FINAL i_idx]
    else:
        t+=['OP_SWAP','OP_DROP','OP_SWAP','OP_DROP'] # drop pi,pf -> [FINAL i_idx]
    # xpos = (offset*omega^i_idx)^(2^li)
    t+=['OP_DUP']                                    # [FINAL i_idx i_idx]  (keep i_idx for ci'/pi')
    t+=[f'<{omega}>','OP_SWAP']                      # [FINAL i_idx omega i_idx]
    t+=[modexp()]                                    # [FINAL i_idx result]
    t+=[f'<{offset}>','OP_MUL',MOD]                  # [FINAL i_idx xpos0]
    for _ in range(li): t+=['OP_DUP','OP_MUL',MOD]   # square li times -> xpos
    # verify hint: inv2x*(2*xpos%P)%P==1
    t+=['OP_2','OP_MUL',MOD,f'<{IX}>','OP_MUL',MOD,'OP_1','OP_NUMEQUALVERIFY']  # [FINAL i_idx]
    # fold value from constants V,W,B,IX,inv2 (computed on-chain)
    t+=[f'<{V}>',f'<{W}>','OP_ADD',MOD,f'<{inv2}>','OP_MUL',MOD]          # e -> [FINAL i_idx e]
    t+=[f'<{V}>',f'<{W}>','OP_SUB',Ph,'OP_ADD',MOD]                       # diff -> [.. e diff]
    t+=[f'<{IX}>','OP_MUL',MOD,f'<{B}>','OP_MUL',MOD]                     # o -> [.. e o]
    t+=['OP_ADD',MOD]                                                     # folded -> [FINAL i_idx folded]
    t+=['OP_OVER']                                  # [FINAL i_idx folded i_idx] = [FINAL ci' pf' pi']
    return ' '.join(t)
prog=[]
prog.append('OP_DROP')  # drop the witness blob from unlocking (provides op-cost budget)
prog.append(f'<0x{final_hex}> <{k0}> OP_0 OP_0')   # [FINAL ci=k0 pf=0 pi=0]
for li in range(nB): prog.append(layer(li))
# final check: final[pi] == pf ; layout [FINAL ci pf pi]
prog.append('OP_8 OP_MUL OP_3 OP_ROLL OP_SWAP OP_SPLIT OP_NIP OP_8 OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM OP_NUMEQUALVERIFY OP_DROP OP_1')
open('fold.asm','w').write('\n'.join(prog))
print('generated fold.asm; layers',nB,'k0',k0,'bytes(asm tokens) ~', sum(len(x.split()) for x in prog))

# tamper hook for negative tests
import sys
if len(sys.argv)>1:
    mode=sys.argv[1]
    if mode=='v': vs[0]^=1
    elif mode=='beta': betas[0]^=1
    elif mode=='inv2x': inv2xs[0]^=1
    elif mode=='final':
        ci=k0
        for li in range(nB): ci=ci%(N//(2**(li+1)))
        b=bytearray(bytes.fromhex(final_hex)); b[ci*8]^=1; final_hex=b.hex()
    # regenerate with tampered value
    prog=['OP_DROP', f'<0x{final_hex}> <{k0}> OP_0 OP_0']
    for li in range(nB): prog.append(layer(li))
    prog.append('OP_8 OP_MUL OP_3 OP_ROLL OP_SWAP OP_SPLIT OP_NIP OP_8 OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM OP_NUMEQUALVERIFY OP_DROP OP_1')
    open('fold.asm','w').write('\n'.join(prog))
    print('TAMPERED:',mode)
