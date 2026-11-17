//! Operand layout + stack contract for every opcode. ONE table used by the compiler
//! (emit), the VM (decode + execute) and the disassembler, so they cannot drift.
//!
//! spec/02 fixes the opcodes and operand *names*; where it does not fix an operand's
//! byte encoding or whether a value travels on the stack, the choice is made HERE and
//! nowhere else. SPEC-GAP: every `Src` below that spec/02 writes as a bare `<a> <b> <off>
//! <size> <len> <sep> <pat> <dir> <list> <buf> <dst> <item> <idx>` is encoded as a full
//! `<src>` (the spec/07 READU32 example does exactly this for `<src> <off>`).
//!
//! # `<src>` encoding
//! `00 idx` user var · `01 id` builtin · `0x80|i` / `FE varint` const (see
//! [`write_src_const`](crate::opcodes::write_src_const)) · `FF` pop from stack.
//! When one instruction has several `FF` sources they are pushed left-to-right by the
//! compiler, so the VM pops them right-to-left (last operand first). Same for PRINT parts.
//!
//! # Stack contract (VM semantics)
//! "push"/"pop" = the value stack of the current frame. `@v` = var slot of the current frame.
//!
//! | op | operands | effect |
//! |---|---|---|
//! | LET | @v cref | @v = const |
//! | MOV | @dst @src | @dst = @src |
//! | STORE | @v | @v = pop |
//! | DUP / SWAP / POP | | as named |
//! | PUSH_VAR | @v | push @v (unset var → runtime error) |
//! | PUSH_CONST | cref | push const |
//! | PUSH_BUILTIN | id:1B | push builtin value (ids: opcodes::BUILTINS) |
//! | GT LT EQ NE GE LE | | pop b, pop a, push int 1/0 (rules: spec/05 "Type system") |
//! | LNOT | @v | push !truthy(@v) |
//! | LAND / LOR | | pop b, pop a, push int 1/0. Short-circuit is done by the compiler: `a; DUP; JZ L; b; LAND; L:` and `a; DUP; JZ R; JMP L; R: b; LOR; L:` — JZ pops the DUP'd copy, so at L the stack holds one value whose truthiness is the result |
//! | NEG / NOT | | pop a, push -a / ~a |
//! | ADD SUB MUL DIV MOD AND OR XOR SHL SHR | | pop b, pop a, push a∘b. ADD also concatenates str+str and buf+buf. Div/mod by zero → runtime error. Int ops wrap (i64) |
//! | JZ | addr | pop; jump if falsy |
//! | JMP | addr | jump |
//! | FOR_RANGE | @v a b | loop var @v from a while < b, step 1. Empty range → jump past the matching FOR_NEXT |
//! | FOR_STEP | @v a b step | same with step (step < 1 → runtime error) |
//! | FOR_EACH | @v arr | @v = each element (arr evaluated once; iterates a snapshot) |
//! | FOR_NEXT | addr | advance innermost loop; if more → jump addr (= first body insn) else drop loop state, fall through |
//! | WHILE | addr | pop cond; if falsy jump addr (loop exit). Layout: `head: cond; WHILE exit; body; JMP head; exit:` |
//! | BREAK / CONTINUE | | no operands: the VM resolves the innermost enclosing loop from a static pre-pass over the code (see "Loop regions") |
//! | CASE | addr | marker only (addr = end of the case statement); no runtime effect |
//! | WHEN | cref addr | pop subject; if subject != const jump addr. Compiler: `subject → STORE @tmp`, then per arm `PUSH_VAR @tmp; WHEN c next; body; JMP end; next:` |
//! | PRINT (0x0060) / PRINT_TUN (0x0005) | n:1B then n × src | stringify + concatenate parts, newline |
//! | INPUT | @v cref | prompt = const; @v = line read from stdin (str, newline stripped); EOF → runtime error (catchable) |
//! | LEN | @v | push length (str = chars, buf = bytes, arr/object/tuple = element count) |
//! | ENDIAN | n:1B | 0 little / 1 big, for typed reads in this frame onward (VM-global state) |
//! | TYPEOF | @v | push "int"/"str"/"buf"/"arr"/"object"/"tuple" ("null" for null) |
//! | CAST | @v type:1B | push cast of @v. 1=int 2=str 3=hex (str of hex digits, from buf or int) 4=buf (from str utf-8) |
//! | CONCAT | | pop b, pop a, push a+b (str+str, buf+buf; else error) |
//! | SUBSTR | | pop len, pop off, pop s, push substring (chars; clamped to end) |
//! | INDEXOF | | pop needle, pop hay, push char index or -1 |
//! | REPLACE | | pop to, pop from, pop s, push s with all `from` → `to` |
//! | SPLIT / JOIN | @v sep | push split(@v, sep) (arr of str) / join(@v, sep) (str) |
//! | TRIM | @v | push trimmed copy |
//! | READ | @v src off size | @v = buf of `size` bytes at `off` |
//! | READU8/16/32/64 | @v src off | @v = int (endian per ENDIAN) |
//! | READSTR | @v src off len | @v = str (utf-8, lossy; trailing NULs stripped) |
//! | FIND | @v buf pat | @v = byte offset of pat (buf or str) in buf, or -1 |
//! | WRITE | buf dst off | write buf (buf or str) to file path `dst` at byte offset `off`; atomic (temp+rename); path must be inside a NEED write root |
//! | ALIGN | @v n:1B | @v (int) rounded up to a multiple of n; n == 0 → runtime error |
//! | PADDING | @v n:1B byte:1B | append `byte` to buf @v until len % n == 0 |
//! | HEX_RANGE | @v off len | push hex string of buf slice |
//! | SLICE | @v off len | push slice of buf/arr/str @v (`len` elements from `off`) |
//! | ARR_NEW | @v | @v = [] |
//! | ARR_GET | @v | pop idx, push @v[idx] (negative = from end; out of range → error) |
//! | ARR_LEN | @v | push len |
//! | ARR_SET | @v idx | pop value; @v[idx] = value |
//! | ARR_PUSH | @v | pop value, append |
//! | ARR_POP | @v | push removed last element (empty → error) |
//! | CONTAINS | @v item | push 1/0 |
//! | OBJ_NEW | @v | @v = {} |
//! | OBJ_GET | @v | pop key, push value or null |
//! | OBJ_SET | @v | pop value, pop key, set (key cast to str; self-reference → error) |
//! | OBJ_HAS | @v | pop key, push 1/0 |
//! | OBJ_KEYS / OBJ_VALUES | @v | push arr (insertion order) |
//! | TUPLE_NEW | n:1B | pop n values (last pushed = last element), push tuple |
//! | TUPLE_GET | idx:1B | pop tuple, push element |
//! | UNPACK | n:1B | pop tuple (len must == n), push elements so the FIRST is on top (`STORE` first var first) |
//! | NEED | kind:1B cref | declare access (kind = PermKind); runtime registers the root for path checks |
//! | GLOB | @v dir pat | @v = arr of matching paths under dir (dir inside a NEED read root) |
//! | SELECT / SELECT_MULTI | @v list cref | prompt user to pick from arr; @v = item / arr |
//! | CALL_FN | fn_id:2B argc:1B | pop argc args (pushed left-to-right) into @0..@argc-1 of a NEW frame (own vars + own stack); on return push the result on the caller's stack. Depth > 256 → runtime error "max recursion depth 256" |
//! | RET | src | return src's value to the caller. Falling off a function's end = return null |
//! | CALL_LIB | @v import_idx:1B fn_id:2B argc:1B | pop argc args; @v = result |
//! | ON_EXIT | addr | register cleanup handler at addr (runs once at exit, 5 s timeout). Compiler: `ON_EXIT h; JMP after; h: body; HALT; after:` |
//! | TRY | addr | push error handler; on a runtime error inside, unwind frames/stack to this point and jump addr |
//! | END_TRY | | pop the innermost handler (normal completion of the try body) |
//! | HALT | | stop, exit code 0 |
//! | EXIT | code:1B cref | print text, stop with code |
//!
//! Jump addresses: 4 bytes little-endian, absolute offset into the code section.
//! 2-byte inline operands (fn_id) are little-endian. Opcodes themselves are big-endian.
//!
//! # Loop regions (for BREAK / CONTINUE)
//! Computed by [`loop_regions`] from bytecode alone:
//! - for-loop: from its FOR_RANGE/FOR_STEP/FOR_EACH insn to the end of its matching FOR_NEXT
//!   (matched by nesting). CONTINUE → jump to the FOR_NEXT insn. BREAK → drop the loop state,
//!   jump past FOR_NEXT.
//! - while-loop: `WHILE exit` at offset w; the insn just before `exit` is `JMP head`. Region =
//!   [head, exit). CONTINUE → head. BREAK → exit.
//! BREAK/CONTINUE use the innermost region containing them.

use crate::opcodes::{Opcode, SRC_BUILTIN, SRC_CONST_ESCAPE, SRC_STACK, SRC_USER_VAR};
use crate::types::Width;
use crate::{varint, FormatError};

/// Kind of one operand in the byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// var index, 1 byte
    Var,
    /// const-pool ref, varint
    CRef,
    /// jump address, 4 bytes LE
    Addr,
    /// plain byte
    U8,
    /// 2 bytes LE (fn_id)
    U16,
    /// entry ref, `width` bytes LE
    Ref,
    /// `<src>` (marker + payload)
    Src,
    /// PRINT: count byte followed by that many `<src>`
    Parts,
}

/// Decoded `<src>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src {
    Var(u8),
    Builtin(u8),
    Const(u64),
    Stack,
}

/// One decoded operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Var(u8),
    CRef(u64),
    Addr(u32),
    U8(u8),
    U16(u16),
    Ref(u64),
    Src(Src),
    Parts(Vec<Src>),
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    pub op: Opcode,
    pub args: Vec<Arg>,
    /// offset of the opcode in the code section
    pub at: usize,
    /// offset of the next instruction
    pub next: usize,
}

/// Operand layout per opcode. The single source of truth.
pub fn operands(op: Opcode) -> &'static [Kind] {
    use Kind::*;
    use Opcode as O;
    match op {
        O::Start | O::Main | O::Halt | O::Nop => &[],
        O::Set | O::Let => &[Var, CRef],
        O::PrintTun | O::Print => &[Parts],
        O::Exit => &[U8, CRef],
        O::Arg => &[Var, CRef, U8, CRef],
        O::Load | O::Run | O::Verify => &[Ref],
        O::LoadSrv => &[Ref, Var],
        O::Perm => &[U8],
        O::Mov => &[Var, Var],
        O::Store | O::PushVar => &[Var],
        O::Dup | O::Swap | O::Pop => &[],
        O::PushConst => &[CRef],
        O::PushBuiltin => &[U8],
        O::Gt | O::Lt | O::Eq | O::Ne | O::Ge | O::Le => &[],
        O::Lnot => &[Var],
        O::Land | O::Lor | O::Neg | O::Not => &[],
        O::Add | O::Sub | O::Mul | O::Div | O::Mod => &[],
        O::And | O::Or | O::Xor | O::Shl | O::Shr => &[],
        O::Jz | O::Jmp | O::ForNext | O::While | O::Case | O::OnExit | O::Try => &[Addr],
        O::Break | O::Continue | O::EndTry => &[],
        O::ForRange => &[Var, Src, Src],
        O::ForStep => &[Var, Src, Src, Src],
        O::ForEach => &[Var, Src],
        O::When => &[CRef, Addr],
        O::Input => &[Var, CRef],
        O::Len | O::Typeof | O::Trim => &[Var],
        O::Endian => &[U8],
        O::Cast => &[Var, U8],
        O::Concat | O::Substr | O::Indexof | O::Replace => &[],
        O::Split | O::Join => &[Var, Src],
        O::Read => &[Var, Src, Src, Src],
        O::ReadU8 | O::ReadU16 | O::ReadU32 | O::ReadU64 => &[Var, Src, Src],
        O::ReadStr => &[Var, Src, Src, Src],
        O::Find => &[Var, Src, Src],
        O::Write => &[Src, Src, Src],
        O::Align => &[Var, U8],
        O::Padding => &[Var, U8, U8],
        O::HexRange | O::Slice => &[Var, Src, Src],
        O::ArrNew | O::ArrGet | O::ArrLen | O::ArrPush | O::ArrPop => &[Var],
        O::ArrSet | O::Contains => &[Var, Src],
        O::ObjNew | O::ObjGet | O::ObjSet | O::ObjHas | O::ObjKeys | O::ObjValues => &[Var],
        O::TupleNew | O::TupleGet | O::Unpack => &[U8],
        O::Need => &[U8, CRef],
        O::Glob => &[Var, Src, Src],
        O::Select | O::SelectMulti => &[Var, Src, CRef],
        O::CallFn => &[U16, U8],
        O::Ret => &[Src],
        O::CallLib => &[Var, U8, U16, U8],
    }
}

fn trunc(at: usize) -> FormatError {
    FormatError::Truncated { what: "instruction operand", offset: at }
}

fn take<'a>(code: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], FormatError> {
    let end = pos.checked_add(n).filter(|&e| e <= code.len()).ok_or(trunc(*pos))?;
    let s = &code[*pos..end];
    *pos = end;
    Ok(s)
}

fn read_varint(code: &[u8], pos: &mut usize) -> Result<u64, FormatError> {
    let (v, n) = varint::decode(code.get(*pos..).ok_or(trunc(*pos))?)?;
    *pos += n;
    Ok(v)
}

fn read_src(code: &[u8], pos: &mut usize) -> Result<Src, FormatError> {
    let at = *pos;
    let m = take(code, pos, 1)?[0];
    Ok(match m {
        SRC_USER_VAR => Src::Var(take(code, pos, 1)?[0]),
        SRC_BUILTIN => Src::Builtin(take(code, pos, 1)?[0]),
        SRC_STACK => Src::Stack,
        SRC_CONST_ESCAPE => Src::Const(read_varint(code, pos)?),
        m if m & 0x80 != 0 => Src::Const((m & 0x7F) as u64),
        m => {
            return Err(FormatError::Invalid {
                what: "<src> marker",
                detail: format!("0x{m:02X} at offset {at}"),
            })
        }
    })
}

/// Decode the instruction at `pc`. Never panics on hostile input.
pub fn decode(code: &[u8], pc: usize, width: Width) -> Result<Insn, FormatError> {
    let mut pos = pc;
    let raw = take(code, &mut pos, 2)?;
    let op = Opcode::try_from(u16::from_be_bytes([raw[0], raw[1]]))?;
    let mut args = Vec::new();
    for k in operands(op) {
        args.push(match k {
            Kind::Var => Arg::Var(take(code, &mut pos, 1)?[0]),
            Kind::U8 => Arg::U8(take(code, &mut pos, 1)?[0]),
            Kind::U16 => {
                let b = take(code, &mut pos, 2)?;
                Arg::U16(u16::from_le_bytes([b[0], b[1]]))
            }
            Kind::Addr => {
                let b = take(code, &mut pos, 4)?;
                Arg::Addr(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            Kind::CRef => Arg::CRef(read_varint(code, &mut pos)?),
            Kind::Ref => {
                let b = take(code, &mut pos, width.bytes())?;
                let mut v = [0u8; 8];
                v[..b.len()].copy_from_slice(b);
                Arg::Ref(u64::from_le_bytes(v))
            }
            Kind::Src => Arg::Src(read_src(code, &mut pos)?),
            Kind::Parts => {
                let n = take(code, &mut pos, 1)?[0];
                let mut parts = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    parts.push(read_src(code, &mut pos)?);
                }
                Arg::Parts(parts)
            }
        });
    }
    Ok(Insn { op, args, at: pc, next: pos })
}

/// Encode a `<src>`.
pub fn write_src(s: Src, out: &mut Vec<u8>) {
    match s {
        Src::Var(i) => out.extend([SRC_USER_VAR, i]),
        Src::Builtin(i) => out.extend([SRC_BUILTIN, i]),
        Src::Const(i) => crate::opcodes::write_src_const(i, out),
        Src::Stack => out.push(SRC_STACK),
    }
}

/// Encode one instruction; `args` must match [`operands`] (checked).
pub fn encode(op: Opcode, args: &[Arg], width: Width, out: &mut Vec<u8>) -> Result<(), FormatError> {
    let bad = |d: &str| FormatError::Invalid { what: "instruction", detail: format!("{}: {d}", op.mnemonic()) };
    let kinds = operands(op);
    if kinds.len() != args.len() {
        return Err(bad("wrong operand count"));
    }
    op.write(out);
    for (k, a) in kinds.iter().zip(args) {
        match (k, a) {
            (Kind::Var, Arg::Var(v)) | (Kind::U8, Arg::U8(v)) => out.push(*v),
            (Kind::U16, Arg::U16(v)) => out.extend(v.to_le_bytes()),
            (Kind::Addr, Arg::Addr(v)) => out.extend(v.to_le_bytes()),
            (Kind::CRef, Arg::CRef(v)) => varint::encode(*v, out),
            (Kind::Ref, Arg::Ref(v)) => width.write(*v, out)?,
            (Kind::Src, Arg::Src(s)) => write_src(*s, out),
            (Kind::Parts, Arg::Parts(p)) => {
                out.push(u8::try_from(p.len()).map_err(|_| bad("more than 255 parts"))?);
                p.iter().for_each(|s| write_src(*s, out));
            }
            _ => return Err(bad("operand kind mismatch")),
        }
    }
    Ok(())
}

/// Decode a whole code section.
pub fn decode_all(code: &[u8], width: Width) -> Result<Vec<Insn>, FormatError> {
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let i = decode(code, pc, width)?;
        pc = i.next;
        out.push(i);
    }
    Ok(out)
}

/// A loop as seen by BREAK/CONTINUE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopRegion {
    /// region = [start, end)
    pub start: usize,
    pub end: usize,
    pub continue_to: usize,
    /// == end
    pub break_to: usize,
    /// true for FOR_* loops: BREAK must drop the loop state
    pub is_for: bool,
}

/// Static loop table (see module docs). Errors on unbalanced FOR_*/FOR_NEXT or a WHILE whose
/// exit is not preceded by `JMP head`.
pub fn loop_regions(insns: &[Insn]) -> Result<Vec<LoopRegion>, FormatError> {
    let bad = |d: String| FormatError::Invalid { what: "loop structure", detail: d };
    let mut out = Vec::new();
    let mut open = Vec::new();
    for (n, i) in insns.iter().enumerate() {
        match i.op {
            Opcode::ForRange | Opcode::ForStep | Opcode::ForEach => open.push(i.at),
            Opcode::ForNext => {
                let start = open.pop().ok_or_else(|| bad(format!("FOR_NEXT at {} without a loop", i.at)))?;
                out.push(LoopRegion { start, end: i.next, continue_to: i.at, break_to: i.next, is_for: true });
            }
            Opcode::While => {
                let Arg::Addr(exit) = i.args[0] else { unreachable!() };
                let exit = exit as usize;
                let head = insns[n..]
                    .iter()
                    .find(|j| j.next == exit)
                    .and_then(|j| match (j.op, j.args.first()) {
                        (Opcode::Jmp, Some(Arg::Addr(h))) if (*h as usize) <= i.at => Some(*h as usize),
                        _ => None,
                    })
                    .ok_or_else(|| bad(format!("WHILE at {}: exit {exit} is not preceded by JMP head", i.at)))?;
                out.push(LoopRegion { start: head, end: exit, continue_to: head, break_to: exit, is_for: false });
            }
            _ => {}
        }
    }
    if let Some(at) = open.pop() {
        return Err(bad(format!("loop at {at} has no FOR_NEXT")));
    }
    Ok(out)
}

/// Innermost region containing `pc`.
pub fn innermost(regions: &[LoopRegion], pc: usize) -> Option<&LoopRegion> {
    regions.iter().filter(|r| r.start <= pc && pc < r.end).min_by_key(|r| r.end - r.start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_round_trips() {
        for &op in Opcode::ALL {
            let args: Vec<Arg> = operands(op)
                .iter()
                .map(|k| match k {
                    Kind::Var => Arg::Var(7),
                    Kind::U8 => Arg::U8(9),
                    Kind::U16 => Arg::U16(0x1234),
                    Kind::Addr => Arg::Addr(0xDEAD_BEEF),
                    Kind::CRef => Arg::CRef(300),
                    Kind::Ref => Arg::Ref(0x0102_0304),
                    Kind::Src => Arg::Src(Src::Const(200)),
                    Kind::Parts => Arg::Parts(vec![Src::Const(2), Src::Var(0), Src::Builtin(1), Src::Stack]),
                })
                .collect();
            for w in [Width::W4, Width::W8] {
                let mut b = Vec::new();
                encode(op, &args, w, &mut b).unwrap();
                let i = decode(&b, 0, w).unwrap();
                assert_eq!((i.op, &i.args, i.next), (op, &args, b.len()), "{}", op.mnemonic());
                for cut in 0..b.len() {
                    assert!(decode(&b[..cut], 0, w).is_err(), "{} cut {cut}", op.mnemonic());
                }
            }
        }
    }

    #[test]
    fn spec07_bytes() {
        // READU32 @2 ← user var @0 (buf), user var @1 (off): `00 73 02 00 00 00 01`
        let mut b = Vec::new();
        encode(Opcode::ReadU32, &[Arg::Var(2), Arg::Src(Src::Var(0)), Arg::Src(Src::Var(1))], Width::W4, &mut b).unwrap();
        assert_eq!(b, [0x00, 0x73, 0x02, 0x00, 0x00, 0x00, 0x01]);
        // PRINT parts=4: #5,@0,#6,@1 → `00 60 04 85 00 00 86 00 01`
        let mut b = Vec::new();
        let parts = vec![Src::Const(5), Src::Var(0), Src::Const(6), Src::Var(1)];
        encode(Opcode::Print, &[Arg::Parts(parts)], Width::W4, &mut b).unwrap();
        assert_eq!(b, [0x00, 0x60, 0x04, 0x85, 0x00, 0x00, 0x86, 0x00, 0x01]);
    }

    #[test]
    fn loops() {
        let w = Width::W4;
        let mut c = Vec::new();
        // 0: FOR_RANGE @0 #0 #1 ; 7: BREAK ; 9: FOR_NEXT 7 ; 15: HALT
        encode(Opcode::ForRange, &[Arg::Var(0), Arg::Src(Src::Const(0)), Arg::Src(Src::Const(1))], w, &mut c).unwrap();
        let body = c.len() as u32;
        encode(Opcode::Break, &[], w, &mut c).unwrap();
        let next_at = c.len();
        encode(Opcode::ForNext, &[Arg::Addr(body)], w, &mut c).unwrap();
        let end = c.len();
        encode(Opcode::Halt, &[], w, &mut c).unwrap();
        let r = loop_regions(&decode_all(&c, w).unwrap()).unwrap();
        assert_eq!(r, [LoopRegion { start: 0, end, continue_to: next_at, break_to: end, is_for: true }]);
        assert!(innermost(&r, body as usize).is_some());
        assert!(innermost(&r, end).is_none());
    }
}
