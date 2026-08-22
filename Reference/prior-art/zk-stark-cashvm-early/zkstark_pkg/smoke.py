from cashvm import VM, P, N, OP, DEFINE, encode_num, decode_num

# 1) BigInt arithmetic past 64 bits
vm = VM()
big = 2**200 + 12345
vm.run([N(big), N(7), OP("MUL")])
assert decode_num(vm.s[-1]) == big*7, "bigint mul"
print("bigint mul ok ->", big*7)

# 2) Loop: sum 1..10 using BEGIN/UNTIL (until counter hits 0)
# stack: acc, i   ; loop: acc+=i ; i-=1 ; push (i==0)
prog = [N(0), N(10),            # acc=0, i=10
        OP("BEGIN"),
          OP("OVER"),           # acc i acc  ... wait design below
        ]
# Cleaner: keep acc on alt, i on main
prog = [N(0), OP("TOALT"),      # alt: acc=0
        N(10),                  # main: i=10
        OP("BEGIN"),
          OP("DUP"), OP("FROMALT"), OP("ADD"), OP("TOALT"),  # acc += i
          N(1), OP("SUB"),                                   # i -= 1
          OP("DUP"), N(0), OP("NUMEQUAL"),                   # push (i==0)
        OP("UNTIL"),
        OP("DROP"), OP("FROMALT")]
vm = VM(); vm.run(prog)
assert decode_num(vm.s[-1]) == 55, decode_num(vm.s[-1])
print("loop sum 1..10 ok ->", decode_num(vm.s[-1]))

# 3) Function: define square(x)=x*x, invoke twice
square = DEFINE([OP("DUP"), OP("MUL")])
prog = [square, N(b"") if False else P(b"\x01"), OP("DEFINE"),  # body, id=0x01, DEFINE
        N(9), P(b"\x01"), OP("INVOKE")]
# fix: DEFINE token already carries body; assembler convention: push id then DEFINE
prog = [ ("PUSH", b"BODY"),  # placeholder body item on stack (real chain: bytecode)
       ]
# Use proper convention: DEFINE token = ("DEFINE", Func(body)); it pops id from stack,
# body is embedded. So we push id, then emit DEFINE.
prog = [ P(b"\x01"), DEFINE([OP("DUP"), OP("MUL")]),   # define func id=01 as x*x
         N(9), P(b"\x01"), OP("INVOKE") ]
vm = VM(); vm.run(prog)
assert decode_num(vm.s[-1]) == 81, decode_num(vm.s[-1])
print("function square(9) ok ->", decode_num(vm.s[-1]))

# 4) Recursive function via INVOKE: factorial
# fid=02: if n<=1 ->1 else n * fact(n-1)
fact_body = [
    OP("DUP"), N(1), OP("GREATERTHAN"),   # n>1 ?
    OP("IF"),
        OP("DUP"), N(1), OP("SUB"), P(b"\x02"), OP("INVOKE"), OP("MUL"),
    OP("ELSE"),
        OP("DROP"), N(1),
    OP("ENDIF"),
]
prog = [ P(b"\x02"), DEFINE(fact_body), N(6), P(b"\x02"), OP("INVOKE") ]
vm = VM(); vm.run(prog)
assert decode_num(vm.s[-1]) == 720, decode_num(vm.s[-1])
print("recursive factorial(6) ok ->", decode_num(vm.s[-1]))
print("ALL SMOKE TESTS PASSED")
