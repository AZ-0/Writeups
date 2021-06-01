from operator import add, sub, mod, and_, or_, mul, floordiv
from collections import defaultdict, deque, namedtuple
from functools import wraps, partial

DEBUG = 0

def flip(f):
    return lambda a, b, *args, **kwargs: f(b, a, *args, **kwargs)

def partialmethod(method, *args, **kwargs):
    return wraps(method)(lambda self, *a, **kwa: method(self, *args, *a, **kwargs, **kwa))

# --- LANGUAGE --- #

def to_name(func, name):
    proxy = partial(func)
    proxy.__name__ = name
    return proxy

def juggle_args(*args, juggler = str, target = str):
    def decorator(func):
        @wraps(func)
        def proxy(a, b):
            ta, tb = type(a), type(b)
            if ta == tb: return func(a, b)
            if ta != target: a = juggler(a)
            if tb != target: b = juggler(b)
            return func(a, b)
        return proxy
    if args: return decorator(args[0])
    return decorator

add = juggle_args(add)
div = to_name(floordiv, 'div')
mult = to_name(mul, 'mult')

def strint(a: str) -> int:
    return int.from_bytes(a.encode('latin1'), 'big')

def intstr(a: int) -> str:
    from Crypto.Util.number import long_to_bytes
    return long_to_bytes(a).decode('latin1')

@juggle_args(juggler=intstr)
def xor(a, b):
    from itertools import cycle
    if type(a) == type(b) == int:
        return a ^ b

    b, a = map(str.encode, sorted([a, b], key=len))
    return bytes(x ^ y for x, y in zip(a, cycle(b))).decode()

def rev(a):
    if type(a) is str: return a[::-1]
    return int(str(a)[::-1])

def pr(a): print(a, end='\n' if DEBUG else '')
def mov(a): return a
def readstr(): return input()
def readint(): return int(input())

def j(process, label):
    process.rip = process.labels[label.name]

def jz(process, value, label):
    if value == 0:
        j(process, label)

def jnz(process, value, label):
    jz(process, not value, label)

def jl(process, less, more, label):
    if less < more:
        j(process, label)

def nameof(f):
    return f.__name__

INSTRUCTIONS = { nameof(f)[: 1 + nameof(f).find('_') or None].rstrip('_') : f for f in (
    readstr, readint, # 0 args
    pr, # 1 arg
    rev, mov, strint, intstr, # 2 args
    add, sub, mult, div, mod, xor, and_, or_, # 3 args
    j, jz, jnz, jl, # Jumps
)}

A0_IS_ARG = { pr, j, jz, jnz, jl }
JUMPS = { j, jz, jnz, jl }

# --- LEXER --- #

Literal = namedtuple('Literal', 'lit')
Value = namedtuple('Value', 'val')

class Lexer():
    def __init__(self, code) -> None:
        self.code: list[str] = code.split('\n')

    def peek(self) -> str:
        return self.line[0] if self.line else None

    def lex(self) -> list:
        ops = []
        for line in map(str.strip, self.code):
            if (op := self.lex_line(line)):
                ops.append(op)
        return ops

    def lex_line(self, line: str):
        self.line, op = deque(line), []
        while self.line:
            if (token := self.lex_token()) is not None:
                op.append(token)
        return op

    def lex_token(self):
        char: str = self.line.popleft()
        if char in ',:[]': return char
        if char == '#':    return self.line.clear()
        if char == '"':    return self.lex_string(char)
        if char.isdigit(): return self.lex_integer(char)
        if char.isalpha(): return self.lex_literal(char)

    def lex_string(self, delim: str) -> Value:
        value = Value(self.lex_generic('', delim.__ne__, map=lambda char: self.line.popleft() if char == '\\' else char))
        self.line.popleft()
        return value

    def lex_integer(self, digit: str) -> Value:
        return Value(int(self.lex_generic(digit, str.isdigit)))

    def lex_literal(self, lit: str) -> Literal:
        return Literal(self.lex_generic(lit, str.isalnum))

    def lex_generic(self, acc, test, map = lambda c: c):
        while (char := self.peek()) is not None and test(char):
            self.line.popleft()
            acc += map(char)
        return acc

# --- PARSER --- #

Operation = namedtuple('Operation', ('name', 'args'))
Register = namedtuple('Register', 'reg')
Address = namedtuple('Address', 'addr')
Label = namedtuple('Label', 'name')

class Parser():
    def __init__(self, code) -> None:
        self.ops = Lexer(code).lex()

    def parse(self):
        return tuple(map(self.parse_op, self.ops))

    def parse_op(self, op):
        self.name, *args = op
        assert type(self.name) is Literal, f"Expected an instruction identifier but got {self.name} instead."
        if args[0] == ':':
            return Label(self.name.lit)
        return Operation(self.name.lit, self.parse_args(args))

    def parse_args(self, tokens):
        self.tokens, args = deque(tokens), []
        while self.tokens:
            args.append(self.parse_arg())
            if self.tokens:
                assert (x := self.tokens.popleft()) == ',', f"Expected `,` (argument separator) but got `{x}` instead."
        return args

    def parse_arg(self):
        token = self.tokens.popleft()
        if token == '(': return self.parse_group(')')
        if token == '[': return Address(self.parse_group(']', 'dereference'))
        if type(token) is Value:   return token.val
        if type(token) is Literal: return self.parse_literal(token.lit)

    def parse_group(self, end, group='group'):
        content = self.parse_arg()
        assert (x := self.tokens.popleft()) == end, f"Expected `{end}` (end of {group}) but got `{x}` instead."
        return content

    def parse_literal(self, literal):
        if INSTRUCTIONS.get(self.name.lit) in JUMPS and ',' not in self.tokens: # last arg of jump instruction
            return Label(literal)
        return Register(literal)

# --- INTERPRETER --- #

class Interpreter:
    def __init__(self, code=None, file=None) -> None:
        if file is not None:
            with open(file, 'r') as file:
                code = file.read()

        self.lines = Parser(code).parse()
        self.memory = [0]*(2**16)
        self.registers = defaultdict(lambda:0)
        self.labels = { line.name : i for i, line in enumerate(self.lines) if type(line) is Label }

    def run(self):
        while self.rip < len(self.lines):
            self.runline(self.lines[self.rip])
            self.rip += 1

    def runline(self, line: Operation):
        if DEBUG: print(line)
        if type(line) is Label:
            return

        self.call(INSTRUCTIONS[line.name], line.args)
        if DEBUG: print(self.registers)

    def get_reg(self, reg):
        return self.registers[reg]

    def set(self, where, val):
        if type(where) is Register:
            where = where.reg
        if type(where) is str:
            self.registers[where] = val
        else:
            self.memory[self.value_of(where.addr)] = val

    def value_of(self, arg):
        ta = type(arg)
        if ta is Register: return self.get_reg(arg.reg)
        if ta is  Address: return self.memory[self.value_of(arg.addr)]
        return arg

    def call(self, inst: callable, raw_args):
        args = map(self.value_of, raw_args[1-(inst in A0_IS_ARG):])
        ret  = inst(self, *args) if inst in JUMPS else inst(*args)

        if ret is not None:
            self.set(raw_args[0], ret)

    rip = property(partialmethod(get_reg, 'rip'), partialmethod(set, 'rip'))

# --- INTERPRETER --- #
Interpreter(file='chall2.s').run()
