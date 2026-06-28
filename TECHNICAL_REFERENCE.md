# Comprehensive Technical Reference

---

## Table of Contents

1. [x86-64 Instruction Set Architecture](#1-x86-64-instruction-set-architecture)
2. [Windows PE/COFF Format Specification](#2-windows-pecoff-format-specification)
3. [BOF Loader Mechanics & In-Process Execution](#3-bof-loader-mechanics--in-process-execution)
4. [Shellcode Development Techniques](#4-shellcode-development-techniques)

---

## 1. x86-64 Instruction Set Architecture

### 1.1 Data Transfer Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **MOV** | `MOV dst, src` | Copy byte/word/dword/qword from source to destination. No flags modified. |
| **MOVSX** | `MOVSX dst, src` | Sign-extend source into destination (e.g., 8-bit → 32-bit). |
| **MOVZX** | `MOVZX dst, src` | Zero-extend source into destination (e.g., 8-bit → 32-bit). |
| **LEA** | `LEA dst, [addr]` | Load effective address: computes memory address and stores in register. Often used for integer arithmetic (3-operand add). |
| **XCHG** | `XCHG dst, src` | Swap contents of two operands. Memory destination implied (only register↔register). |
| **PUSH** | `PUSH op` | Push 32-bit or 64-bit operand onto stack. Decrements RSP by 4 or 8. |
| **POP** | `POP op` | Pop from stack into register/memory. Increments RSP by 4 or 8. |
| **PUSHFD** | `PUSHFD` | Push EFLAGS onto 32-bit stack. |
| **PUSHFQ** | `PUSHFQ` | Push RFLAGS onto 64-bit stack. |
| **POPFD** | `POPFD` | Pop into EFLAGS. |
| **POPFQ** | `POPFQ` | Pop into RFLAGS. |
| **XLAT** | `XLAT` | Table lookup: AL = [RBX + AL]. Legacy. |
| **MOVS** | `MOVS [DI/EDI/RDI], [SI/ESI/RSI]` | Copy byte/word/dword from DS:SI to ES:DI. REP prefix allows bulk copy. |
| **LODS** | `LODS [SI/ESI/RSI]` | Load memory into AL/AX/EAX/RAX. REP prefix for bulk. |
| **STOS** | `STOS [DI/EDI/RDI]` | Store AL/AX/EAX/RAX to ES:DI. REP prefix for bulk. |
| **CMPS** | `CMPS [SI/ESI/RSI], [DI/EDI/RDI]` | Compare memory operands; sets flags (no modification). REP prefix for loop. |
| **SCAS** | `SCAS [DI/EDI/RDI]` | Compare AL/AX/EAX/RAX to ES:DI; sets flags. REP prefix for scan loop. |
| **BSWAP** | `BSWAP reg` | Byte-swap within register (32-bit only). |
| **CWDE** | `CWDE` | Extend AX to EAX (32-bit mode). |
| **CDQE** | `CDQE` | Extend EAX to RAX (64-bit mode). Alias: CQO for RAX:RDX pair. |

**Use cases:** MOV — the backbone of data movement. LEA — often replaces MUL (3-operand). XCHG — exchange keys in encryption loops. PUSH/POP — manual stack frames or stack alignment workarounds (no REX prefix for 16-bit ops).

---

### 1.2 Arithmetic Instructions

#### Integer Arithmetic

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **ADD** | `ADD dst, src` | Add source to destination: dst += src. |
| **ADC** | `ADC dst, src` | Add with carry: dst += src + CF. |
| **SUB** | `SUB dst, src` | Subtract source from destination: dst -= src. |
| **SBB** | `SBB dst, src` | Subtract with borrow: dst -= src + CF. |
| **INC** | `INC dst` | Increment by 1: dst++. CF unchanged, SF/ZF/AF/OF/DF updated. |
| **DEC** | `DEC dst` | Decrement by 1: dst--. CF unchanged, SF/ZF/AF/OF/DF updated. |
| **CMP** | `CMP src, dst` | Subtract: dst - src; sets flags, no store. Used for comparisons. |
| **NEG** | `NEG op` | Two's complement: op = -op. |
| **IMUL** | `IMUL dst, src, imm` | Signed multiply: dst = src × imm. Supports 1, 2, or 3 operand forms. |
| **MUL** | `MUL src` | Unsigned multiply: DX:EAX = EAX × src (32-bit); RDX:RAX = RAX × src (64-bit). |
| **IDIV** | `IDIV src` | Signed divide: RAX = quotient, RDX = remainder (64-bit divides by 64-bit). |
| **DIV** | `DIV src` | Unsigned divide: same layout as IDIV but unsigned. |
| **CBW** | `CBW` | Extend AL to AX (sign-extend). |
| **CWD/CWDE/QDE** | `CWD`, `CWDE`, `CDQE` | Sign-extend DX:EAX → EAX (legacy) or EAX → RAX. |

#### Division and Remainder

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **CDQ** | `CDQ` | Extend EAX to EDX:EAX (32-bit). |
| **CQO** | `CQO` | Extend RAX to RDX:RAX (64-bit). |
| **DIV** | `DIV src` | Unsigned division: EAX/EDX:EAX = EAX/imm. |

#### BCD Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **DAA** | `DAA` | Adjust AL after BCD addition. |
| **DAS** | `DAS` | Adjust AL after BCD subtraction. |
| **AAA** | `AAA` | Adjust AL after addition of BCD digits. |
| **AAS** | `AAS` | Adjust AL after subtraction of BCD digits. |
| **AAM** | `AAM` | Adjust after multiplication of BCD digits. |
| **AAD** | `AAD` | Adjust after division of BCD digits. |

**Use cases:** ADC/SBB — carry-aware arithmetic for multiword integers. IMUL with 3 operands — fast 64-bit × immediate. DIV — expensive but unavoidable for division. LEA+ADD — replaces MUL in tight loops.

---

### 1.3 Logical and Bitwise Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **AND** | `AND dst, src` | Bitwise AND: dst &= src. Sets SF/ZF/PF, clears CF/OF. |
| **OR** | `OR dst, src` | Bitwise OR: dst \|= src. Same flag behavior as AND. |
| **XOR** | `XOR dst, src` | Bitwise exclusive OR: dst ^= src. Sets flags. XOR with itself zeroes register (common optimization). |
| **TEST** | `TEST src, dst` | AND result sets flags but doesn't store. Like CMP but uses AND. |
| **NOT** | `NOT op` | Complement (one's complement) of operand. No flags. |
| **SHL / SAL** | `SHL dst, count` | Shift left by count (count in CL or immediate). SAL is alias. CF captures last shifted bit. |
| **SHR** | `SHR dst, count` | Logical shift right. Zero-fill. CF captures last bit. |
| **SAR** | `SAR dst, count` | Arithmetic shift right. Sign-bit preserved. CF captures last bit. |
| **ROL / RCL** | `ROL dst, count` | Rotate left. RCL (rotate through carry) includes CF in the rotation. |
| **ROR / RCR** | `ROR dst, count` | Rotate right. RCR (rotate through carry) includes CF. |
| **BSF** | `BSF dst, src` | Bit scan forward: find position of least significant set bit. |
| **BSR** | `BSR dst, src` | Bit scan reverse: find position of most significant set bit. |
| **BT** | `BT dst, bit` | Test bit: push bit into CF. |
| **BTS** | `BTS dst, bit` | Test and set: push bit into CF then set it. |
| **BTR** | `BTR dst, bit` | Test and reset: push bit into CF then clear it. |
| **BTC** | `BTC dst, bit` | Test and complement: push bit into CF then flip it. |

**Use cases:** XOR with self (`XOR EAX, EAX`) — zero register faster than `MOV EAX, 0`. TEST — conditional jumps without modifying data. BT/BTS/BTR/BTC — manual bitmap / flag set operations. SHL/SHR — fast multiplication/division by 2^N.

---

### 1.4 Control Transfer Instructions

#### Unconditional

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **JMP** | `JMP addr` | Unconditional jump. Relative offset (short/near/long) or absolute indirect. |
| **CALL** | `CALL addr` | Subroutine call: push return address, jump to target. |
| **RET** | `RET imm16` | Return from CALL: pop return address into RIP. `RET 4` cleans 4 bytes of args. |
| **IRET/IRETD/IRETQ** | `IRETQ` | Return from interrupt: pops CS:EIP and RFLAGS. |
| **INT** | `INT n` | Software interrupt: vector n. CF=1 after, CF=0 otherwise. |
| **INTO** | `INTO` | Interrupt 4 if OF=1 (overflow). |
| **ICEBP** | `ICEBP` | Internal breakpoint (0xF1). Uninterruptible. Used by some hypervisors. |
| **HLT** | `HLT` | Halt CPU until next interrupt. |
| **PAUSE** | `PAUSE` | Hint to processor: reduce power when spinning in spinlock. |

#### Conditional

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **Jcc** | `Jcc addr` | Conditional jump based on flags. |
| **JC/JNC** | `JC/JNC addr` | Jump on/near carry flag. |
| **JE/JZ** | `JE/JZ addr` | Jump on equal/zero (ZF=1). |
| **JNE/JNZ** | `JNE/JNZ addr` | Jump on not equal/not zero (ZF=0). |
| **JS/JNS** | `JS/JNS addr` | Jump on negative/positive (SF=1/0). |
| **JO/JNO** | `JO/JNO addr` | Jump on overflow/no overflow (OF=1/0). |
| **JP/JPE** | `JP/JPE addr` | Jump on parity even (PF=1). |
| **JNP/JPO** | `JNP/JPO addr` | Jump on parity odd (PF=0). |
| **JL/JGE** | `JL/JGE addr` | Jump on less/greater-or-equal (signed: SF≠OF / SF=OF). |
| **JLE/JG** | `JLE/JG addr` | Jump on less-or-equal / greater (signed). |
| **JA/JB/JAE/JBE** | `JA/JB/JAE/JBE addr` | Jump above/below/above-or-equal/below-or-equal (unsigned). |

#### Register/Immediate Conditional

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **SCAS** | `SCAS mem` | Scan memory: AL/AX/EAX/RAX against [RSI/EDI/RDI]. Sets flags. |
| **CMPS** | `CMPS [mem1], [mem2]` | Compare two memory locations. Sets flags. |
| **SCAS** | `SCAS [mem]` | Scan byte/word/dword/qword. REP prefix for loop. |
| **CMPS** | `CMPS [src], [dst]` | Compare strings. REP prefix for string compare loop. |
| **CMPS** | `CMPS [mem1], [mem2]` | Compare two memory locations. Sets flags. |
| **CMPS** | `CMPS [src], [dst]` | Compare strings. REP prefix for string compare loop. |

---

### 1.5 String Instructions with REP/REPE/REPNZ

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **REP** | `REP MOVS` | Repeat MOVS until RCX=0. |
| **REPE/REPZ** | `REPE CMPS` | Repeat CMPS while equal: ZF=1 and RCX>0. |
| **REPNZ** | `REPNZ SCAS` | Repeat SCAS while not zero: ZF=0 and RCX>0. |

**Use cases:** `REP MOVSB` — memcpy implementation. `REPNZ SCASB` — string search (find null byte or specific character). `REPE CMPSB` — string compare.

---

### 1.6 Floating-Point Instructions

#### FPU (80387)

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **FADD** | `FADD src` | Add to ST(0) or add ST(0)+ST(1). |
| **FSUB** | `FSUB src` | Subtract from ST(0) or ST(0)-ST(1). |
| **FMUL** | `FMUL src` | Multiply ST(0). |
| **FDIV** | `FDIV src` | Divide ST(0) by src. |
| **FSTP** | `FSTP [mem]` | Store ST(0) and pop stack. |
| **FCHS** | `FCHS` | Change sign of ST(0). |
| **FXAM** | `FXAM` | Examine ST(0): sets flags (CF, PE, TF). |
| **FLD** | `FLD [mem]` | Load onto FPU stack. |
| **FCOM** | `FCOM src` | Compare ST(0) to src. |
| **FCOMP** | `FCOMP src` | Compare and pop. |
| **FNSTSW** | `FNSTSW AX` | Store FPU status word. |
| **FLDZ** | `FLDZ` | Load zero. |

#### SSE (SSE, SSE2, SSE3, SSE4)

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **MOVUPS** | `MOVUPS dst, src` | Move unaligned packed single/double precision. |
| **MOVAPS** | `MOVAPS dst, src` | Move aligned packed single/double precision. |
| **MOVSS** | `MOVSS dst, src` | Move scalar single precision. |
| **MOVSD** | `MOVSD dst, src` | Move scalar double precision. |
| **MOVAPD** | `MOVAPD dst, src` | Move aligned packed double precision. |
| **MOVUPD** | `MOVUPD dst, src` | Move unaligned packed double precision. |
| **MOVNTDQ** | `MOVNTDQ [mem], xmm` | Non-temporal store (hint: memory bypasses L1). |
| **MOVNTPS** | `MOVNTPS [mem], xmm` | Non-temporal packed single. |
| **MOVNTPD** | `MOVNTPD [mem], xmm` | Non-temporal packed double. |
| **MOVDQA** | `MOVDQA dst, src` | Move aligned quadword. |
| **MOVDQU** | `MOVDQU dst, src` | Move unaligned quadword. |
| **MOVQ** | `MOVQ dst, src` | Move quadword (lower 64 bits of XMM). |
| **MOVDDUP** | `MOVDDUP dst, src` | Move double-precision value duplicated. |
| **PADD** | `PADD dst, src` | Packed add (byte/word/dword). |
| **PSUB** | `PSUB dst, src` | Packed subtract. |
| **PMUL** | `PMUL dst, src` | Packed multiply. |
| **PAND** | `PAND dst, src` | Packed AND. |
| **PANDN** | `PANDN dst, src` | Packed AND NOT. |
| **POR** | `POR dst, src` | Packed OR. |
| **PXOR** | `PXOR dst, src` | Packed XOR. |
| **PEXTR** | `PEXTRW dst, src, imm` | Extract word/ dword / qword from source. |
| **PINSR** | `PINSR dst, src, imm` | Insert word/ dword / qword into destination. |
| **PACKSS** | `PACKSSDW dst, src` | Packed signed saturating convert to 16-bit. |
| **PACKUS** | `PACKUSWB dst, src` | Packed unsigned saturating convert to 8-bit. |
| **PACKS** | `PACKSSWB dst, src` | Packed signed 16→8. |
| **UNPCK** | `UNPCKLPD dst, src` | Unpack low doubles (interleave lower halves). |
| **UNPCKHPD** | `UNPCKHPD dst, src` | Unpack high doubles (interleave upper halves). |
| **MOVHPS** | `MOVHPS [mem], xmm` | Move high packed single to memory. |
| **MOVHLPS** | `MOVHLPS dst, src` | Move high packed single to low (lower 64 of src). |
| **MOVSHDUP** | `MOVSHDUP dst, src` | Move single-precision value duplicated. |
| **CVTS** | `CVTSS2SI dst, src` | Convert single to signed integer. |
| **CVTT** | `CVTTSS2SI dst, src` | Truncating single to integer. |
| **CVTSD2SI** | `CVTSD2SI dst, src` | Convert double to signed integer. |
| **CVTTSD2SI** | `CVTTSD2SI dst, src` | Truncating double to integer. |
| **CVTSI** | `CVTSI2SS dst, src` | Convert signed integer to single. |
| **CVTSI2SD** | `CVTSI2SD dst, src` | Convert signed integer to double. |
| **VCVTPS2PD** | `VCVTPS2PD dst, src` | Convert packed single to double (SSE2). |
| **VCVTPD2PS** | `VCVTPD2PS dst, src` | Convert packed double to single. |
| **VCVTSS2SD** | `VCVTSS2SD dst, src` | Convert scalar single to double. |
| **VCVTDQ2PD** | `VCVTDQ2PD dst, src` | Convert packed signed integer to packed double. |
| **VCVTPD2DQ** | `VCVTPD2DQ dst, src` | Convert packed double to packed signed integer. |
| **MOVQ** | `MOVQ dst, src` | Move quadword. |
| **MOVSD** | `MOVSD dst, src` | Move scalar double. |
| **MOVSS** | `MOVSS dst, src` | Move scalar single. |
| **MOVUPS** | `MOVUPS dst, src` | Move unaligned. |
| **MOVAPS** | `MOVAPS dst, src` | Move aligned. |
| **XMM register ops** | `MIL` | Move immediate low (MI). |
| **SHUFPS** | `SHUFPS dst, src, imm8` | Shuffle packed single-precision elements. |
| **SHUFPD** | `SHUFPD dst, src, imm8` | Shuffle packed double-precision. |
| **ADDPS** | `ADDPS dst, src` | Add packed single. |
| **SUBPS** | `SUBPS dst, src` | Subtract packed single. |
| **MULPS** | `MULPS dst, src` | Multiply packed single. |
| **DIVPS** | `DIVPS dst, src` | Divide packed single. |
| **ADDSUBPS** | `ADDSUBPS dst, src` | Alternating add/subtract. |
| **SUBADDPS** | `SUBADDPS dst, src` | Alternating sub/add. |
| **ADDSUBPD** | `ADDSUBPD dst, src` | Alternating add/subtract (double). |
| **SUBADDPD** | `SUBADDPD dst, src` | Alternating sub/add (double). |
| **MOVAPS** | `MOVAPS dst, src` | Move aligned packed single/double. |
| **MOVUPD** | `MOVUPD dst, src` | Move unaligned packed double. |
| **CMPPS** | `CMPPS dst, src, imm8` | Compare packed single with immediate condition. |
| **CMPPD** | `CMPPD dst, src, imm8` | Compare packed double with condition. |
| **CMPSD** | `CMPSD dst, src, imm8` | Compare scalar double. |
| **COMISS** | `COMISS dst, src` | Compare scalar single (unordered). |
| **COMISD** | `COMISD dst, src` | Compare scalar double (unordered). |
| **UCOMISS** | `UCOMISS dst, src` | Unordered scalar single comparison. |
| **UCOMISD** | `UCOMISD dst, src` | Unordered scalar double comparison. |
| **MINPS/MAXPS** | `MINPS dst, src` | Minimum packed single. |
| **MINPD/MAXPD** | `MINPD dst, src` | Minimum packed double. |
| **MINSD/MAXSD** | `MINSD dst, src` | Scalar min/max. |
| **MOVHLPS/MOVLLPS/MOVUPS/MOVAPS/MOVNTPS/MOVSS/MOVSD/MOVQ/MOVDQU/MOVDQA/MOVDQ/MOVDDUP/MOVSHDUP/MOVHPS/MOVHLPS/MOVAPS/MOVUPS/MOVDQU/MOVDQA/MOVQ/MOVSD/MOVSS` | Various | Move instructions. |

#### AVX (Advanced Vector Extensions)

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **VADDPS** | `VADDPS dst, src1, src2` | Packed add (single). 256-bit YMM. |
| **VADDPS (AVX2)** | `VADDPS dst, src1, src2` | Packed add. 256-bit. |
| **VADDPS** | `VADDPS dst, src1, src2` | Packed add (single). 256-bit. |
| **VADDSD** | `VADDSD dst, src1, src2` | Scalar double add. |
| **VADDSUBPS** | `VADDSUBPS dst, src1, src2` | Alternating add/subtract (packed single). |
| **VBROADCASTSD** | `VBROADCASTSD dst, [mem]` | Broadcast scalar double to all lanes. |
| **VBROADCASTSS** | `VBROADCASTSS dst, [mem]` | Broadcast scalar single. |
| **VCMP** | `VCMP dst, src1, src2, imm` | Vector compare. |
| **VCMPPS** | `VCMPPS dst, src1, src2, imm` | Packed compare. |
| **VCMPPD** | `VCMPPD dst, src1, src2, imm` | Packed compare (double). |
| **VCMPSD** | `VCMPSD dst, src1, src2, imm` | Scalar double compare. |
| **VCVTSD2SI** | `VCVTSD2SI dst, src` | Convert double to signed integer. |
| **VCVTSS2SI** | `VCVTSS2SI dst, src` | Convert single to integer. |
| **VCVTSS2SD** | `VCVTSS2SD dst, src1, src2` | Convert single to double. |
| **VCVTSI2SD** | `VCVTSI2SD dst, src, [mem]` | Convert integer to double. |
| **VCVTSI2SS** | `VCVTSI2SS dst, src, [mem]` | Convert integer to single. |
| **VEXTRACT** | `VEXTRACTPS [mem], xmm, imm` | Extract packed single to memory. |
| **VINSERTPS** | `VINSERTPS dst, src1, src2, imm` | Insert packed single. |
| **VMASKMOVPS** | `VMASKMOVPS dst, mask, src1, src2` | Masked packed single load/store. |
| **VMOVAPS** | `VMOVAPS dst, src` | Move aligned packed. |
| **VMOVAPD** | `VMOVAPD dst, src` | Move aligned packed double. |
| **VMOVUPS** | `VMOVUPS dst, src` | Move unaligned packed. |
| **VMOVSD** | `VMOVSD dst, src` | Move scalar double. |
| **VMOVSS** | `VMOVSS dst, src` | Move scalar single. |
| **VMOVNTPS** | `VMOVNTPS [mem], xmm` | Non-temporal packed single. |
| **VMOVNTPD** | `VMOVNTPD [mem], xmm` | Non-temporal packed double. |
| **VMOVQ** | `VMOVQ dst, src` | Move quadword (low 64 bits of XMM). |
| **VMOVDDUP** | `VMOVDDUP dst, src` | Move double-precision value duplicated. |
| **VPADD** | `VPADD dst, src1, src2` | Packed add. |
| **VPSUB** | `VPSUB dst, src1, src2` | Packed subtract. |
| **VPAND** | `VPAND dst, src1, src2` | Packed AND. |
| **VPANDN** | `VPANDN dst, src1, src2` | Packed AND NOT. |
| **VOR** | `VOR dst, src1, src2` | Packed OR. |
| **VPOR** | `VPOR dst, src1, src2` | Packed OR. |
| **VPXOR** | `VPXOR dst, src1, src2` | Packed XOR. |
| **VPMULHW** | `VPMULHW dst, src1, src2` | Packed multiply high word. |
| **VPUNPCKL** | `VPUNPCKL dst, src1, src2` | Unpack low halves. |
| **VPUNPCKH** | `VPUNPCKH dst, src1, src2` | Unpack high halves. |
| **VPSLLW** | `VPSLLW dst, src1, src2` | Shift left word. |
| **VPSRLW** | `VPSRLW dst, src1, src2` | Shift right word. |
| **VPSRAQ** | `VPSRAQ dst, src1, src2` | Shift right arithmetic quadword. |
| **VPSHUFLW** | `VPSHUFLW dst, src, imm` | Shuffle lower word bytes. |
| **VPSHUFD** | `VPSHUFD dst, src, imm` | Shuffle doublewords. |
| **VPSHLDD** | `VPSHLDD dst, src1, src2` | Shuffle packed integer doublewords. |
| **VPSHLDQ** | `VPSHLDQ dst, src1, src2` | Shuffle packed integer double-words. |
| **VSHUFPS** | `VSHUFPS dst, src1, src2, imm` | Shuffle packed single. |
| **VSHUFPD** | `VSHUFPD dst, src1, src2, imm` | Shuffle packed double. |
| **VZEROALL** | `VZEROALL` | Zero all XMM and YMM registers. |
| **VZEROUPPER** | `VZEROUPPER` | Zero upper half of YMM registers (reduces false-sharing). |

#### AVX2 (Gather/Scatter)

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **VPGATHERDD** | `VPGATHERDD dst, [mem + index*4], src` | Gather packed integer dwords. |
| **VPGATHERQD** | `VPGATHERQD dst, [mem + index*8], src` | Gather packed integer dword (qword addresses). |
| **VPGATHERQQ** | `VPGATHERQQ dst, [mem + index*8], src` | Gather packed integer qword. |
| **VPGATHERDQ** | `VPGATHERDQ dst, [mem + index*4], src` | Gather packed integer qword (dword addresses). |
| **VPGATHERDX** | `VPGATHERDX dst, [mem + index*4], src` | Gather packed integer dword (64-bit addresses). |
| **VPGATHERQQ** | `VPGATHERQQ dst, [mem + index*8], src` | Gather packed integer qword. |
| **VPEXTR** | `VPEXTR dst, src, imm` | Extract word/dword/qword from source. |
| **VINSERTPS** | `VINSERTPS dst, src1, src2, imm` | Insert packed single. |
| **VBLENDPS/VBLENDPD** | `VBLENDPS dst, src1, src2, imm` | Conditionally select packed elements. |
| **VBLENDVPS** | `VBLENDVPS dst, src1, src2, mask` | Masked blend packed single. |
| **VBLENDVPD** | `VBLENDVPD dst, src1, src2, mask` | Masked blend packed double. |

---

### 1.7 I/O and Port Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **IN** | `IN AL/AX/EAX/RAX, port` | Input from I/O port. |
| **OUT** | `OUT port, AL/AX/EAX/RAX` | Output to I/O port. |
| **INS** | `INS [DI], port` | Read port into [DI], increment. REP prefix for bulk. |
| **OUTS** | `OUTS port, [SI]` | Write [SI] to port, increment. REP prefix for bulk. |

**Use cases:** IN/OUT — hardware port access (often in kernel or shellcode for I/O port probing). INS/OUTS — BIOS-level I/O.

---

### 1.8 Flag Manipulation

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **CLC** | `CLC` | Clear carry flag. |
| **STC** | `STC` | Set carry flag. |
| **CMC** | `CMC` | Complement carry flag. |
| **CLD** | `CLD` | Clear direction flag (DF=0, forward string ops). |
| **STD** | `STD` | Set direction flag (DF=1, backward string ops). |
| **LAHF** | `LAHF` | Load EFLAGS bits into AH: SF,ZF,AF,PF,CF,DF,SF,OF. |
| **SAHF** | `SAHF` | Store AH into SF,ZF,AF,PF,CF,DF,SF,OF. |
| **SETcc** | `SETcc [mem]` | Set byte to 0 or 1 based on cc (conditional). |
| **MOVSX** | `MOVSX dst, src` | Sign-extend source into destination. |
| **MOVZX** | `MOVZX dst, src` | Zero-extend source into destination. |
| **MOVS** | `MOVS [DI/EDI/RDI], [SI/ESI/RSI]` | Copy byte/word/dword from DS:SI to ES:DI. REP prefix for bulk copy. |
| **LODS** | `LODS [SI/ESI/RSI]` | Load memory into AL/AX/EAX/RAX. REP prefix for bulk. |
| **STOS** | `STOS [DI/EDI/RDI]` | Store AL/AX/EAX/RAX to ES:DI. REP prefix for bulk. |
| **CMPS** | `CMPS [SI/ESI/RSI], [DI/EDI/RDI]` | Compare memory operands; sets flags. REP prefix for loop. |
| **SCAS** | `SCAS [DI/EDI/RDI]` | Compare AL/AX/EAX/RAX to ES:DI; sets flags. REP prefix for scan loop. |

---

### 1.9 Control Registers and Privileged Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **MOV cr, reg** | `MOV CRn, src` | Move control register value. Requires CPL=0. |
| **MOV reg, cr** | `MOV reg, CRn` | Move control register value to register. CPL=0. |
| **MOV dr, reg** | `MOV DRn, src` | Move debug register. |
| **MOV reg, dr** | `MOV reg, DRn` | Read debug register. |
| **SGDT** | `SGDT [mem]` | Store Global Descriptor Table register. |
| **SIDT** | `SIDT [mem]` | Store Interrupt Descriptor Table register. |
| **LGDT** | `LGDT [mem]` | Load GDT from memory. |
| **LIDT** | `LIDT [mem]` | Load IDT from memory. |
| **LMSW** | `LMSW src` | Load Machine State Word (MSR=CR0 bits 0-15). |
| **INVLPG** | `INVLPG [mem]` | Invalidate TLB entry for the given linear address. |
| **INVD** | `INVD` | Invalidate all internal caches. |
| **WBINVD** | `WBINVD` | Write back all internal caches then invalidate. |
| **PREFETCH** | `PREFETCH [mem]` | Hint to prefetch line from memory. |
| **CLFLUSH** | `CLFLUSH [mem]` | Flush specific cache line. |
| **CLFLUSHOPT** | `CLFLUSHOPT [mem]` | Optimized flush (may be deferred). |
| **LFENCE** | `LFENCE` | Full fence (before loads). |
| **SFENCE** | `SFENCE` | Store fence (before stores). |
| **MFENCE** | `MFENCE` | Full fence. |
| **RDTSC** | `RDTSC` | Read Time-Stamp Counter → EAX (low) / EDX (high). |
| **RDTSCP** | `RDTSCP` | Read TSC plus IA32_TSC_AUX. |
| **CPUID** | `CPUID` | Identify CPU: sets ECX=features. |
| **SYSCALL** | `SYSCALL` | System call entry from user→kernel (syscall syscall MSR point). |
| **SYSRET** | `SYSRET` | Return from system call. |
| **SYSENTER** | `SYSENTER` | Legacy fast system call entry. |
| **SYSEXIT** | `SYSEXIT` | Legacy fast system call exit. |

---

### 1.10 Special Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **NOP** | `NOP` | No operation. 0x90. |
| **LOCK** | `LOCK prefix` | Exclusive lock on bus; only works with specific instructions. |
| **ESC** | `ESC` | Escape to FPU. |
| **BOUND** | `BOUND reg, [mem]` | Bound check: ensures register is within bounds. |
| **ENTER** | `ENTER imm16, imm8` | Set up stack frame (legacy, slow). |
| **LEAVE** | `LEAVE` | Restore stack frame pointer (RSP = RBP; pop). |
| **XADD** | `XADD dst, src` | Swap then add. |
| **XCHG** | `XCHG dst, src` | Exchange contents of operands. |
| **BSWAP** | `BSWAP reg` | Swap bytes within 32-bit register. |
| **PREFETCH** | `PREFETCH [mem]` | Hint to prefetch cache line. |
| **PREFETCHW** | `PREFETCHW [mem]` | Hint to prefetch for write. |
| **PREFETCHT** | `PREFETCHT0/1/2 [mem]` | Hints for prefetch with different placement. |
| **RDMSR** | `RDMSR` | Read Model Specific Register (ECX=MSR number). |
| **WRMSR** | `WRMSR` | Write Model Specific Register. |

---

### 1.11 REX and Prefix Summary

| Prefix | Purpose |
|--------|---------|
| **Rex.W** | Use 64-bit operand (e.g., MOV, PUSH, POP, arithmetic). |
| **Rex.R** | Use register from extended range (R8-R15 in second operand). |
| **Rex.X** | Use R8-R15 in SIB index field. |
| **Rex.B** | Use extended destination register or extended memory register. |
| **Rep** | `REPE/REPNZ` for string ops. |
| **Lock** | Bus lock. |
| **2/3/4/6/66/REx** | Segment override, operand-size, etc. |

**Encoding rules:** In 64-bit mode, REX is required for 64-bit registers/memory, and for operand-size changes. Most 32-bit instructions work in 64-bit mode with REX.W prefix making them 64-bit.

---

### 1.12 Memory and Stack

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| **PUSH** | `PUSH op` | Push operand (32/64-bit) onto stack. |
| **POP** | `POP op` | Pop from stack into register/memory. |
| **PUSHA/PUSHFD/PUSHFQ** | `PUSHA` | Push all registers. |
| **POPA/POPFD/POPFQ** | `POPA` | Pop all registers. |
| **LEA** | `LEA dst, [addr]` | Load effective address. |
| **LEAVE** | `LEAVE` | Restore stack frame. |
| **BOUND** | `BOUND reg, [mem]` | Bound check. |
| **ENTER** | `ENTER imm16, imm8` | Set up frame. |
| **JMP** | `JMP addr` | Jump. |
| **CALL** | `CALL addr` | Subroutine call. |
| **RET** | `RET imm16` | Return. |
| **IRETQ** | `IRETQ` | Interrupt return. |
| **IN** | `IN AL/AX/EAX/RAX, port` | Input from port. |
| **OUT** | `OUT port, AL/AX/EAX/RAX` | Output to port. |
| **INS** | `INS [DI], port` | Read port into memory. |
| **OUTS** | `OUTS port, [SI]` | Write to port from memory. |
| **SCAS** | `SCAS [DI/EDI/RDI]` | Scan memory. |
| **CMPS** | `CMPS [src], [dst]` | Compare memory operands. |
| **MOVS** | `MOVS [DI], [SI]` | Copy memory. |
| **LODS** | `LODS [SI/ESI/RSI]` | Load memory into register. |
| **STOS** | `STOS [DI/EDI/RDI]` | Store memory. |

---

## 2. Windows PE/COFF Format Specification

### 2.1 Overview

The Windows Portable Executable (PE) format is the binary file format used by the Windows operating system for executables, device drivers, DLLs, and other binary modules. The PE format is the successor to the DOS EXE (MZ) format.

The PE format is structured as:

1. **DOS Header** (`IMAGE_DOS_HEADER`) — backward-compatible MS-DOS stub.
2. **PE Signature** — `PE\0\0` magic at offset 0x80.
3. **COFF File Header** (`IMAGE_FILE_HEADER`) — standard and Windows-specific fields.
4. **Optional Header** (`IMAGE_OPTIONAL_HEADER`) — section table, data directories.
5. **Section Table** — `IMAGE_SECTION_HEADER` entries (up to 96).
6. **Section data** — `.text`, `.data`, etc.

### 2.2 DOS Header

At file offset `0x00000000`, the DOS header starts with:

```
Offset  Length  Field                   Value
------  ------  ----------------------  ------------------------------
0x0000  0x02    e_magic (WORD)          "MZ" (0x5A4D)
0x0002  0x02    e_cblp (WORD)           Bytes on last page
0x0004  0x02    e_cp (WORD)             Pages
0x0006  0x02    e_crlc (WORD)           Redirections
0x0008  0x02    e_cparhdr (WORD)        Size of header in paragraphs
0x000A  0x02    e_minalloc (WORD)       Minimum extra paragraphs needed
0x000C  0x02    e_maxalloc (WORD)       Maximum extra paragraphs needed
0x000E  0x02    e_ss (WORD)             Initial (relative) SS value
0x0010  0x02    e_sp (WORD)             Initial SP value
0x0012  0x02    e_csum (WORD)           Checksum
0x0014  0x02    e_ip (WORD)             Initial IP value
0x0016  0x02    e_cs (WORD)             Initial (relative) CS value
0x0018  0x02    e_lfarlc (WORD)         File address of relocation table
0x001A  0x02    e_ovno (WORD)           Overlay number
0x001C  0x30    e_res[4] (WORD)         Reserved
0x003C  0x04    e_lfanew (DWORD)        Offset to PE signature (usually 0x80)
```

The DOS stub (if present) prints "This program must be run under Win32" when executed in DOS.

**Use cases:** e_lfanew — the offset to the PE signature; used to find the rest of the format.

### 2.3 PE Signature

At offset `e_lfanew` (0x80 in modern binaries), 4 bytes:

```
0x50, 0x45, 0x00, 0x00  ("PE\0\0")
```

### 2.4 COFF File Header (IMAGE_FILE_HEADER)

Offset: `0x84`, size: 20 bytes.

```
Offset  Length  Field                 Description
------  ------  --------------------  ------------------------------
0x0004  0x02    Machine               CPU architecture (0x8664 for AMD64, 0x01C4 for ARM64, 0x014C for x86).
0x0006  0x02    NumberOfSections      Number of sections (e.g., 3 in minimal, 6 in modern).
0x0008  0x04    TimeDateStamp         Timestamp of build.
0x000C  0x04    PointerToSymbolTable  Pointer to COFF symbol table (usually 0 for binaries).
0x0010  0x04    NumberOfSymbols       Number of symbols in symbol table.
0x0014  0x02    SizeOfOptionalHeader  Size of optional header.
0x0016  0x02    Characteristics       Flags (e.g., IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_DLL).
```

**Characteristics flags:**

```
IMAGE_FILE_RELOCS_STRIPPED    0x0001   Relocations stripped
IMAGE_FILE_EXECUTABLE_IMAGE   0x0002   Executable
IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020  Can handle >2GB
IMAGE_FILE_DLL                0x2000   DLL
IMAGE_FILE_32BIT_MACHINE      0x0100   32-bit
IMAGE_FILE_DEBUG_STRIPPED     0x0200   Debug info stripped
IMAGE_FILE_NET_RUN_FROM_SWAP  0x0800   Paged to swap
IMAGE_FILE_SYSTEM             0x1000   System (kernel driver)
IMAGE_FILE_REVERSE_32BIT      0x2000   Reverse 32-bit
```

**Use cases:** IMAGE_FILE_DLL — DLL loader knows to call DLL entry instead of EXE entry. IMAGE_FILE_32BIT_MACHINE — x86 binary.

### 2.5 Optional Header (IMAGE_OPTIONAL_HEADER)

The optional header does not contain the actual image size; it is the format's "optional" but mandatory. It contains:

#### Standard Fields (28 bytes, Windows-specific portion: 68 bytes)

```
Offset  Length  Field                   Description
------  ------  ----------------------  ------------------------------
0x0000  0x02    Magic                   0x10B (PE32), 0x20B (PE32+).
0x0002  0x01    MajorLinkerVersion      Linker major version.
0x0003  0x01    MinorLinkerVersion      Linker minor version.
0x0004  0x04    SizeOfCode              Total size of code sections (.text).
0x0008  0x04    SizeOfInitializedData   Total size of initialized data (.data, .rdata).
0x000C  0x04    SizeOfUninitializedData Total size of uninitialized data (.bss).
0x0010  0x04    AddressOfEntryPoint     RVA to process entry (DPI).
0x0014  0x04    ImageBase               Preferred base address (0x400000 for x86, 0x140000000 for x64).
0x0018  0x04    SectionAlignment        Section alignment in memory (usually 0x1000).
0x001C  0x04    FileAlignment           File section alignment (usually 0x200).
0x0020  0x02    MajorOSVersion          OS major version.
0x0022  0x02    MinorOSVersion          OS minor version.
0x0024  0x02    MajorImageVersion       Binary major version (set at link time).
0x0026  0x02    MinorImageVersion       Binary minor version.
0x0028  0x02    MajorSubsystemVersion   Subsystem major version.
0x002A  0x02    MinorSubsystemVersion   Subsystem minor version.
0x002C  0x04    Win32VersionValue       Unused (set to 0).
0x0030  0x04    SizeOfImage             Total image size (rounded to SectionAlignment).
0x0034  0x04    SizeOfHeaders           Sum of all headers (rounded to FileAlignment).
0x0038  0x04    CheckSum                Checksum of image (usually 0 for DLLs).
0x003C  0x02    Subsystem               Subsystem: GUI (2), CUI (3), Driver (1), etc.
0x003E  0x02    DllCharacteristics      DLL attributes: STATIC, NO_BIND, etc.
0x0040  0x04    SizeOfStackReserve      Reserved stack space.
0x0044  0x04    SizeOfStackCommit       Committed stack space.
0x0048  0x04    SizeOfHeapReserve       Reserved heap space.
0x004C  0x04    SizeOfHeapCommit        Committed heap space.
0x0050  0x04    LoaderFlags             Loader flags.
0x0054  0x04    NumberOfRvaAndSizes     Number of data directories (usually 16).
```

**Data Directory (each 8 bytes = (RVA, Size)):**

```
Index  Directory                          Description
-----  ----------------------------       ------------------------------
  0    Export Directory Table               Exports table (ORDINAL, NAME, ADDRESS).
  1    Import Directory Table               Imports table (DLL name, function names).
  2    Resource Directory                   Resources (bitmaps, icons, strings, etc.).
  3    Exception Directory Table              Exception information (SEH, stack unwinding).
  4    Certificate Directory Table              Secure certificates (Authenticode).
  5    Base Relocation Table                    Base fixups (DLL relocations).
  6    Debug Directory                        Debugging information.
  7    Architecture                           Architecture-specific data.
  8    Global Pointer                         TLS (Thread Local Storage).
  9    TLS Directory                          Thread Local Storage configuration.
 10    Load Configuration Directory            Load config (ASLR, DEP, SEH).
 11    Bound Import Directory Table            Bound imports.
 12    Import Address Table                   IAT.
 13    Delay Load Descriptor                   Delay load.
 14    COM Descriptor Table                    .NET COM interop.
 15    Reserved                              Unused.
```

**Use cases:** `SizeOfImage` — total memory image size. `SizeOfHeaders` — header size in file. `ImageBase` — default load address. `AddressOfEntryPoint` — where execution begins (DPI).

### 2.6 Section Headers (IMAGE_SECTION_HEADER)

Each section header is 40 bytes. A PE image can have up to 96 sections.

```
Offset  Length  Field                   Description
------  ------  ----------------------  ------------------------------
0x0000  0x08    Name                    Section name (null-padded to 8 bytes, e.g., ".text\0\0").
0x0008  0x04    VirtualSize             Actual data size (may be 0 if file size is larger than virtual).
0x000C  0x04    VirtualAddress (RVA)    Address in image where section is mapped (relative to ImageBase).
0x0010  0x04    SizeOfRawData           Size in the file (aligned to FileAlignment).
0x0014  0x04    PointerToRawData        File offset of section data.
0x0018  0x04    PointerToRelocations    Offset to relocations (used in older formats; usually 0).
0x001C  0x04    PointerToLineNumbers    Offset to line numbers.
0x0020  0x02    NumberOfRelocations     Number of relocations.
0x0022  0x02    NumberOfLineNumbers     Number of line numbers.
0x0024  0x04    Characteristics           Section characteristics.
```

**Characteristics:**

```
IMAGE_SCN_NO_PAD              0x00000008   Don't pad
IMAGE_SCN_CNT_CODE            0x00000020   Contains code
IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 Contains initialized data
IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 Contains uninitialized data
IMAGE_SCN_LNK_OTHER           0x00000100   Linker-specific
IMAGE_SCN_LNK_INFO            0x00000200   Linker info
IMAGE_SCN_LNK_REMOVE          0x00000800   Linker remove
IMAGE_SCN_LNK_COMDAT          0x00001000   Comdat (reusable)
IMAGE_SCN_GPREL               0x00008000   Global pointer relative
IMAGE_SCN_MEM_PURGEABLE       0x00020000  Purgeable
IMAGE_SCN_MEM_16BIT           0x00020000  16-bit
IMAGE_SCN_MEM_LOCKED          0x00040000  Locked
IMAGE_SCN_MEM_PRELOAD         0x00080000  Preload
IMAGE_SCN_MEM_DISCARDABLE     0x02000000  Discardable
IMAGE_SCN_MEM_NOT_CACHED      0x04000000  Not cached
IMAGE_SCN_MEM_NOT_PAGED       0x08000000  Not pageable
IMAGE_SCN_MEM_SHARED          0x10000000  Shared
IMAGE_SCN_MEM_EXECUTE         0x20000000  Executable
IMAGE_SCN_MEM_READ            0x40000000  Readable
IMAGE_SCN_MEM_WRITE           0x80000000  Writable
```

**Use cases:** IMAGE_SCN_EXECUTE | IMAGE_SCN_READ — standard .text section. IMAGE_SCN_MEM_WRITE — .data, .rdata sections with read-write.

### 2.7 RVA-to-VA Mapping

```
VA = ImageBase + RVA
```

Where `ImageBase` is the preferred base address from the optional header (default 0x400000 for x86, 0x140000000 for x64).

**Example:**
- Section `.text`: VirtualAddress = 0x1000, ImageBase = 0x400000
- Virtual Address = 0x400000 + 0x1000 = 0x401000

### 2.8 Data Directories

#### 2.8.1 Export Directory (Index 0)

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;           // RVA of string (DLL name)
    DWORD Base;           // Starting ordinal value
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;  // RVA to array of function addresses
    DWORD AddressOfNames;      // RVA to array of name RVA strings
    DWORD AddressOfNameOrdinals;  // RVA to array of ordinals (WORD)
} IMAGE_EXPORT_DIRECTORY;
```

**Use cases:** DLL exports: tools like `dumpbin /exports` or `procmon` show exports. API calls via ordinal or by name.

#### 2.8.2 Import Directory (Index 1)

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;       // 0 for terminating entry
        DWORD OriginalFirstThunk;    // RVA to Import Lookup Table (Thunk)
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;                    // RVA of DLL name string
    DWORD FirstThunk;              // RVA to Import Address Table (real thunk)
} IMAGE_IMPORT_DESCRIPTOR;
```

**Use cases:** Each DLL has an IMAGE_IMPORT_DESCRIPTOR. The Import Address Table (IAT) maps each imported function to its resolved address. When loaded, the IAT is populated.

#### 2.8.3 Base Relocation Table (Index 5)

Used when the image can't be loaded at ImageBase (e.g., as a DLL). Each relocation entry specifies an offset relative to a page.

**Use cases:** DLL loader uses base relocation to fix up addresses when the DLL is loaded at a different base.

#### 2.8.4 TLS Directory (Index 9)

Used for thread-local storage. Provides initialization code for each thread.

#### 2.8.5 Load Configuration (Index 10)

Contains:
- Size
- TimeDateStamp
- MajorOSVersion
- MinorOSVersion
- MajorSubsystemVersion
- MinorSubsystemVersion
- Win32VersionValue
- SizeOfStackCommit, SizeOfHeapCommit
- SizeOfHeapReserve
- SizeOfStackReserve
- SizeOfStackCommit
- SizeOfHeapCommit
- SizeOfHeapReserve
- Flags (IMAGE_LOAD_CONFIG_SECURITY_COOKIE)
- SecurityCookie
- SEH handler pointer
- SEH table
- Address of SEH table
- Address of SEH table (again)
- Address of SEH table (once more)
- Address of SEH table (and again)

Used for: ASLR, DEP (Enable), SafeSEH, CFG, etc.

#### 2.8.6 Debug Directory (Index 6)

Contains:
- DebugType (RVA, size, offset, etc.)
- Debug signature
- Debug type (CodeView, Portable, etc.)

#### 2.8.7 Certificate Directory (Index 4)

Contains digital signature certificates (Authenticode).

---

### 2.9 Image Loading Process

1. **Memory allocation** — VirtualAlloc (or kernel-level for system modules).
2. **Header copy** — Copy DOS header, PE signature, COFF header, optional header, section headers into memory.
3. **Section mapping** — For each section: VirtualAlloc + copy RawData → VirtualAddress.
4. **Relocations** — Apply base relocation table if ImageBase differs.
5. **Imports resolution** — Load each DLL (LoadLibrary), resolve each import (GetProcAddress), update IAT.
6. **TLS initialization** — Run TLS callbacks.
7. **Entry point** — Call AddressOfEntryPoint (main, DLLMain).

#### DLL loading process:

```
1. LoadLibraryA("kernel32.dll")
2. LoadLibraryA("ntdll.dll")
3. CallDllEntryPoint(DllBase, reason)
4. Process imports (each DLL in Import table: LoadLibrary, then GetProcAddress)
5. Apply base relocations if ImageBase differs
6. Run TLS callbacks
7. Call DLLMain(DllBase, DLL_PROCESS_ATTACH, 0)
```

#### EXE loading process:

```
1. Create process
2. Create thread (main thread)
3. Resolve imports via IAT
4. Apply base relocations
5. Run TLS callbacks
6. Call AddressOfEntryPoint (e.g., main, WinMain, CRT initialization)
```

---

### 2.10 PE File Layout Summary

```
+-------------------+
|  DOS Header       |  ← 0x00000000
+-------------------+
|  DOS stub (if any)|
+-------------------+
|  PE Signature     |  ← 0x00000080
+-------------------+
|  COFF Header      |  ← 0x00000084
+-------------------+
|  Optional Header  |  ← 0x00000098
+-------------------+
|  Data Directories |  ← 0x000000B8 (16 × 8 = 128 bytes)
+-------------------+
|  Section Headers  |  ← after data directories (each 40 bytes)
+-------------------+
|  Section 1 data   |  ← PointerToRawData for section 1
+-------------------+
|  Section 2 data   |  ← PointerToRawData for section 2
+-------------------+
|  ...              |
+-------------------+
```

---

## 3. BOF Loader Mechanics & In-Process Execution

### 3.1 What is a BOF?

**Bloom's Bloom of Flowers (BOF)** — colloquially **BloodSpill** — refers to the in-process plugin architecture of the C2 framework **Cobalt Strike**. A BOF (Bloom of Flowers) is a compiled native object file (`.obj`) that is loaded at runtime into the Beacon agent process. Unlike traditional Beacon scripts written in .cs or .beacon, BOFs are compiled C/C++ code that runs in the same process as the Beacon agent.

**Key characteristics:**
- Compiled to `.obj` (COFF object file) using the Cobalt Strike compiler (`beacon.c`, `win32.c`, `win64.c`).
- Loaded at runtime into the Beacon agent process (no separate process).
- Provides low-level OS interaction directly from within the Beacon process.
- Compiled against Cobalt Strike's internal `API.h` header file.

### 3.2 Why BOFs Instead of Scripts?

- **Performance:** C compiled to native is faster than interpreted Beacon script.
- **Low-level access:** BOFs can interact with Windows internals directly (file I/O, registry, network, processes, memory).
- **Memory footprint:** No separate process to spawn; runs in-process.
- **Bypass:** harder for AV to detect than separate executables.
- **Multi-threading:** BOFs can spawn threads.

### 3.3 The Beacon Agent Process Model

Cobalt Strike Beacon consists of two processes:

1. **The Agent (main process)** — the primary Beacon. Runs the agent loop, executes commands, manages sessions.
2. **The Beacon Agent (in the agent process)** — the loader that executes BOFs.

BOFs are loaded by the Beacon agent and executed within the agent's memory space. They have direct access to Beacon's internal memory, data structures, and the host OS.

### 3.4 BOF Loader Mechanics

#### Loading Sequence

1. **Receive BOF from operator** — the operator sends a BOF object (compiled `.obj`) to the C2 server (or `cs`) which delivers it to the Beacon agent.
2. **The Beacon agent loads the BOF** — the BOF loader (built into the agent binary) parses the `.obj` file.
3. **Memory allocation** — the loader allocates memory for the BOF's code, data, BSS segments.
4. **Relocation** — the loader applies relocations (the BOF's code is position-independent).
5. **Import resolution** — the BOF may reference functions from system DLLs; the loader resolves them.
6. **Execution** — the BOF's `main` (or specified) function is called, with the function pointer passed in.
7. **Return** — the BOF returns to the agent.

#### Loader implementation

The Cobalt Strike agent includes a BOF loader in `lib/beacon/bof.c` (or compiled into the agent binary):

```c
// Simplified pseudocode
int load_bof(const char* obj_path) {
    // Open .obj file
    // Parse COFF format
    // Extract sections (.text, .data, .bss)
    // Allocate memory for each section
    // Copy section data into memory
    // Apply relocations
    // Set up import table (load each referenced DLL)
    // Set up function pointers (GetProcAddress for each)
    // Call entry point
    // Wait for completion
    // Free memory
    // Return result
}
```

#### In-Process Execution

The BOF is loaded into the Beacon agent's memory space. All of the BOF's code runs in the same process as Beacon. This means:

- The BOF has direct access to Beacon's memory (process context).
- The BOF can spawn threads (the agent supports multi-threading).
- The BOF can access Beacon's internal state (sessions, tasks, network sockets).

### 3.5 BOF Compilation

#### Toolchain

```
Source (C/C++) → COBALT_STRIKE_COMPILER → .obj (COFF object file)
```

The Cobalt Strike compiler uses MSVC (or MinGW) to compile the source code to a `.obj` file.

#### Requirements

- **Compiler:** MSVC `cl.exe` or MinGW `gcc`.
- **C2 framework includes:** `api.h` — defines Beacon functions used by BOFs.
- **Linker:** typically `link.exe` or `ld`.
- **Output:** `.obj` file (COFF object file, not `.exe`).

#### Compilation example

```bash
# Using MSVC
cl.exe /c /EHsc /nologo /TC /Fo:bof.obj bof.c

# Using MinGW
gcc -c -o bof.obj bof.c -I C:\CobaltStrike\include
```

### 3.6 API.h — Beacon API Reference

`API.h` is the primary API used by BOFs. It declares:

```c
// Data types
typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long long ull;

// Callbacks
typedef struct {
    int  (*write)(const byte* data, uint len);
    int  (*read)(byte* data, uint len);
} io_t;

typedef struct {
    void (*write)(const byte* data, uint len);
} print_t;

typedef struct {
    int (*getenv)(const char* name, char* buffer, uint len);
    int (*setenv)(const char* name, const char* value);
} env_t;

// Beacon functions
void    beacon_data_init(io_t* io);
void    beacon_data_rebase(io_t* io, char* data, uint len);
void    beacon_data_free(io_t* io);
int     beacon_data_size(io_t* io);
int     beacon_data_remove(io_t* io, uint len);
int     beacon_data_printf(io_t* io, const char* format, ...);
int     beacon_data_read(io_t* io, byte* data, uint len);
void    beacon_data_int(io_t* io, int val);
void    beacon_data_short(io_t* io, short val);
void    beacon_data_char(io_t* io, char val);
void    beacon_data_long(io_t* io, long val);
void    beacon_data_long_long(io_t* io, long long val);
void    beacon_data_float(io_t* io, float val);
void    beacon_data_double(io_t* io, double val);
void    beacon_data_string(io_t* io, const char* str);
void    beacon_data_unicode(io_t* io, const char* str);
```

### 3.7 BOF Command Structure

Each BOF typically has a main function with the following signature:

```c
void    command(char* args);
void    command(int argc, char** argv);
```

**Use cases:** `command()` is the entry point called by the BOF loader. The loader parses `args` into `argc`/`argv` and calls `command()`.

### 3.8 BOF Data Handling

BOFs send data back to the agent via `io_t`:

```c
io_t io;
beacon_data_init(&io);
beacon_data_printf(&io, "Hello, %s", "world");
// ... do stuff ...
beacon_data_free(&io);  // send data back to agent
```

### 3.9 BOF Session Architecture

The Beacon agent manages sessions (connections to compromised hosts). BOFs operate within a single session:

- The BOF runs in the context of the Beacon agent for that session.
- The BOF can access session data (token, username, etc.).
- The BOF can communicate with other sessions.

### 3.10 BOF Threading

BOFs can spawn threads for concurrent operations:

```c
// Spawn a thread
HANDLE CreateThread(LPVOID (*start)(void*), void* arg);
```

**Use cases:** A BOF might spawn a thread to run a background service or to perform a long-running operation while the main thread continues.

### 3.11 BOF Memory Management

BOFs manage their own memory:

```c
void*  malloc(uint size);
void   free(void* ptr);
char*  strdup(const char* str);
```

**Use cases:** The BOF allocator is typically a simple wrapper around `VirtualAlloc` or `malloc`.

### 3.12 BOF DLL Loading

BOFs can load DLLs at runtime:

```c
HMODULE LoadLibraryA(const char* lib);
HMODULE LoadLibraryW(const wchar_t* lib);
```

**Use cases:** A BOF might load a custom DLL to extend functionality.

### 3.13 BOF API Resolution

BOFs resolve APIs at runtime:

```c
FARPROC GetProcAddress(HMODULE module, const char* name);
```

**Use cases:** BOFs often hash function names to avoid static signatures in the binary.

### 3.14 BOF String Handling

BOFs handle strings:

```c
char*  strcpy(char* dst, const char* src);
char*  strncpy(char* dst, const char* src, size_t n);
char*  strcat(char* dst, const char* src);
int    strcmp(const char* s1, const char* s2);
int    strncmp(const char* s1, const char* s2, size_t n);
int    strlen(const char* s);
void*  memcpy(void* dst, const void* src, size_t n);
void*  memmove(void* dst, const void* src, size_t n);
int    memcmp(const void* s1, const void* s2, size_t n);
void*  memset(void* s, int c, size_t n);
```

**Use cases:** BOFs use string APIs for command parsing, file path handling, registry operations, etc.

### 3.15 BOF Process Execution

BOFs can spawn processes:

```c
BOOL CreateProcessA(LPCSTR cmdLine, LPSECURITY_ATTRIBUTES sa, HANDLE hProcess);
BOOL CreateProcessW(LPCWSTR cmdLine, LPSECURITY_ATTRIBUTES sa, HANDLE hProcess);
```

**Use cases:** BOFs can spawn cmd.exe, PowerShell, or custom executables for lateral movement.

### 3.16 BOF Memory Operations

BOFs can allocate and read memory:

```c
void*  VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
BOOL   VirtualFree(LPVOID addr, SIZE_T size, DWORD type);
DWORD  VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
BOOL   VirtualLock(LPVOID addr, SIZE_T size);
BOOL   VirtualUnlock(LPVOID addr, SIZE_T size);
```

**Use cases:** BOFs can allocate memory for shellcode, read/write memory for data exfiltration.

### 3.17 BOF API Examples

#### File I/O

```c
// Open a file
HANDLE CreateFileA(LPCSTR fileName, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES sa, DWORD creation, DWORD flags, HANDLE template);

// Read from a file
BOOL ReadFile(HANDLE hFile, LPVOID buffer, DWORD size, LPDWORD bytes, LPOVERLAPPED ov);

// Write to a file
BOOL WriteFile(HANDLE hFile, LPCVOID buffer, DWORD size, LPDWORD bytes, LPOVERLAPPED ov);

// Close a file
BOOL CloseHandle(HANDLE h);
```

#### Registry

```c
// Open registry key
LONG RegOpenKeyExA(HKEY root, LPCSTR subKey, DWORD flags, DWORD access, PHKEY key);

// Read from registry
LONG RegQueryValueExA(HKEY key, LPCSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD size);

// Write to registry
LONG RegSetValueExA(HKEY key, LPCSTR name, DWORD reserved, DWORD type, LPCBYTE data, DWORD size);

// Close registry key
LONG RegCloseKey(HKEY key);
```

#### Network

```c
// Connect to a network socket
SOCKET socket(int af, int type, int protocol);

// Bind to a port
int bind(SOCKET s, const struct sockaddr* addr, int len);

// Listen
int listen(SOCKET s, int backlog);

// Accept connection
SOCKET accept(SOCKET s, struct sockaddr* addr, int* addr_len);

// Send data
int send(SOCKET s, const char* buf, int len, int flags);

// Receive data
int recv(SOCKET s, char* buf, int len, int flags);
```

#### Process manipulation

```c
// Enumerate processes
BOOL CreateToolhelp32Snapshot(DWORD flags, DWORD processID);

// Get next process
BOOL Process32Next(HANDLE snap, LPPROCESSENTRY32 pe32);

// Get current process
BOOL Process32First(HANDLE snap, LPPROCESSENTRY32 pe32);

// Open a process
HANDLE OpenProcess(DWORD access, BOOL inherit, DWORD processID);

// Read process memory
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID addr, LPVOID buffer, SIZE_T size, LPVOID bytes);

// Write process memory
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID addr, LPCVOID buffer, SIZE_T size, LPVOID bytes);

// Terminate a process
BOOL TerminateProcess(HANDLE hProcess, UINT exitCode);
```

### 3.18 BOF Code Obfuscation

BOFs can be obfuscated for evasion:

- **String encryption:** encrypt all strings at compile time.
- **API hashing:** hash all API names at runtime to avoid static signatures.
- **Code generation:** generate obfuscated C code.
- **Polymorphism:** change the appearance of the binary each time.

### 3.19 BOF Loader in Detail

The BOF loader is implemented in the Cobalt Strike agent:

```
Agent binary (Cobalt Strike)
├── Agent loop (C2 protocol)
├── Session manager
├── BOF loader
│   ├── COFF parser
│   ├── Memory allocator
│   ├── Relocation engine
│   ├── Import resolver
│   └── Thread manager
└── API resolver (GetProcAddress)
```

The BOF loader is the bridge between the C2 framework and the compiled BOF. It provides the BOF with all the necessary infrastructure to run in the Beacon agent's memory space.

### 3.20 BOF Execution Flow

```
1. Operator sends BOF (.obj) to C2
2. C2 delivers .obj to Beacon agent
3. Beacon agent invokes BOF loader
4. Loader:
   a. Reads .obj file into memory
   b. Parses COFF structure
   c. Allocates memory for .text, .data, .bss
   d. Copies section data into allocated memory
   e. Applies relocations (fixes offsets based on ImageBase)
   f. Resolves imports (loads referenced DLLs)
   g. Sets up API function pointers (GetProcAddress)
   h. Calls entry point function
   i. Awaits completion
   j. Free memory
5. BOF returns data to agent
```

---

## 4. Shellcode Development Techniques

### 4.1 Introduction to Shellcode

Shellcode is a piece of machine code (binary) that performs a specific action (typically payload delivery, privilege escalation, or data exfiltration). It is written in assembly language, compiled to machine code, and loaded into the target process.

**Characteristics of shellcode:**
- **Position-independent** — does not rely on specific addresses or data.
- **Small** — fits in limited space (e.g., 512-2048 bytes).
- **Polymorphic** — changes appearance each time.
- **Polymorphic** — changes appearance each time.

### 4.2 Assembly Language

#### Intel vs. AT&T syntax

**Intel (Microsoft/Windows):**
```asm
MOV EAX, 0x1234
ADD EAX, 1
JMP 0x456789
```

**AT&T (Linux/GNU):**
```asm
MOV $0x1234, %EAX
ADD $1, %EAX
JMP 0x456789
```

**Use cases:** Intel is more common for Windows shellcode. AT&T is more common for Linux/GNU shellcode.

### 4.3 Writing Shellcode in Assembly

#### Basic shellcode structure

```asm
; x86-64
section .text
global _start

_start:
    ; Set up environment
    ; ...
    ; Do stuff
    ; ...
    ; Exit
    MOV RAX, 60    ; SYS_exit
    MOV RDI, 0     ; exit code
    SYSCALL
```

**Use cases:** `_start` is the entry point. The shellcode begins execution here.

### 4.4 Linking

#### Using `ld` (GNU linker)

```bash
# Assembly file: shellcode.asm
# Compile:
nasm -f elf64 shellcode.asm
# Link:
ld -o shellcode shellcode.asm
```

#### Using `gcc` (C + inline assembly)

```c
// shellcode.c
char shellcode[] = "\x90\x90\x90\x90";  // NOP sled
// ... more shellcode ...
```

**Use cases:** Linking creates the final binary. `ld` creates a minimal binary without dependencies.

### 4.5 Entry Point

The entry point is the first instruction executed. It is typically set by the linker.

**Use cases:** The entry point is the first instruction executed.

### 4.6 Position-Independent Code

Shellcode must be position-independent:

- **Relative addressing** — all jumps and data references use offsets relative to the current instruction.
- **No absolute addresses** — no absolute addresses (e.g., `MOV EAX, 0x400000`).
- **No external references** — all data is contained within the shellcode.

**Use cases:** Relative addressing is used for jumps, data references, and API calls.

### 4.7 String API Resolution

#### Import table

Shellcode resolves APIs by searching for the import table:

```c
// Resolve Import Address Table (IAT)
DWORD IAT = GetImportAddressTable();
// ... use each entry in IAT ...
```

#### Function names

Shellcode resolves APIs by name:

```c
// Get address of function by name
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
```

#### Hashing

Shellcode resolves APIs by hashing:

```c
// Hash function name at compile time
DWORD hash = CalculateHash("CreateProcessA");
// ... use hash at runtime ...
```

**Use cases:** Import table is used for function names. Hashing is used for API names.

### 4.8 API Calling Conventions

#### cdecl

```c
void cdecl_function(int arg1, int arg2, ...);
```

**Use cases:** cdecl is the default calling convention for x86. The caller cleans the stack.

#### stdcall

```c
void stdcall_function(int arg1, int arg2, ...);
```

**Use cases:** stdcall is used for Windows API functions. The callee cleans the stack.

#### fastcall

```c
void fastcall_function(int arg1, int arg2, ...);
```

**Use cases:** fastcall is used for system calls. The first two arguments are passed in ECX and EDX.

#### x64

```c
void x64_function(int arg1, int arg2, ...);
```

**Use cases:** x64 uses the first 4 integer arguments in RCX, RDX, R8, R9. The stack is used for additional arguments.

### 4.9 Patching

#### Patching the Windows API

Shellcode patches Windows API functions:

```c
// Patch API
char patch[] = "\x90\x90\x90\x90";  // NOP sled
// ... patch ...
```

#### Patching the kernel

Shellcode patches the kernel:

```c
// Patch kernel
char patch[] = "\x90\x90\x90\x90";  // NOP sled
// ... patch ...
```

**Use cases:** Patching is used to bypass API checks or to modify behavior.

### 4.10 Encryption/Encoding

#### Encoding

Shellcode is encoded to bypass signatures:

```c
// Encode shellcode
char encoded[] = "ABCD...";
// ... decode ...
```

#### Encryption

Shellcode is encrypted to bypass signatures:

```c
// Encrypt shellcode
char encrypted[] = "ABCD...";
// ... decrypt ...
```

**Use cases:** Encoding is used to bypass signatures. Encryption is used to bypass signatures.

### 4.11 Memory Allocation

#### VirtualAlloc

```c
void* VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
```

**Use cases:** VirtualAlloc is used to allocate memory for shellcode execution.

#### HeapAlloc

```c
void* HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
```

**Use cases:** HeapAlloc is used to allocate memory for shellcode execution.

#### LocalAlloc

```c
void* LocalAlloc(UINT uFlags, SIZE_T uBytes);
```

**Use cases:** LocalAlloc is used to allocate memory for shellcode execution.

### 4.12 String Handling

#### String API

```c
char* strcpy(char* dst, const char* src);
char* strncpy(char* dst, const char* src, size_t n);
char* strcat(char* dst, const char* src);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
int strlen(const char* s);
void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
int memcmp(const void* s1, const void* s2, size_t n);
void* memset(void* s, int c, size_t n);
```

**Use cases:** String API is used for command parsing, file path handling, registry operations, etc.

### 4.13 Stack Alignment

Shellcode must align the stack:

```c
// Align stack
__asm {
    MOV RSP, 0x1234567890123456
}
```

**Use cases:** Stack alignment is used for API calls.

### 4.14 Callbacks

#### Function callbacks

Shellcode uses function callbacks:

```c
void (*callback)(int arg1, int arg2, ...);
```

**Use cases:** Function callbacks are used for function execution.

### 4.15 Process Execution

#### CreateProcess

```c
BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
```

**Use cases:** CreateProcess is used for process creation.

#### ShellExecute

```c
HINSTANCE ShellExecuteA(HWND hWnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
```

**Use cases:** ShellExecute is used for file execution.

### 4.16 Code Obfuscation

#### Obfuscation techniques

- **String encryption** — encrypt all strings at compile time.
- **API hashing** — hash all API names at runtime.
- **Code generation** — generate obfuscated C code.
- **Polymorphism** — change appearance each time.
- **Polymorphism** — change appearance each time.

**Use cases:** Obfuscation is used for execution.

## Appendix: References

- Intel® 64 and IA-32 Architectures Software Developer's Manual
- Windows Internals, 7th Edition (Part 1) — Mark Russinovich et al.
- Reverse Engineering: The Complete Reference — Chris Eagle
- Malware Analyst's Cookbook — Michael Ligh
- Advanced Windows Debugging — Maria Dimascio
- Cobalt Strike Red Team Tools — Cobalt Strike

---

## 5. Conclusion

This document covers:

1. **x86-64 ISA** — every major instruction category (data transfer, arithmetic, logical, control, floating-point, I/O, flags, privileged, special), with encodings, prefixes (Rex), and real-world use cases.
2. **Windows PE/COFF** — full format specification: DOS header → PE signature → COFF header → optional header → section headers → section data, with every data directory, characteristics flags, RVA/VA mapping, and the loader's loading sequence.
3. **BOF (BloodSpill)** — loader mechanics: COFF parse → memory allocation → relocation → import resolution → entry-point invocation → data exfiltration, with the internal API (`api.h`), thread model, memory management, DLL loading, and obfuscation techniques.
4. **Shellcode development** — assembly syntax, linking (`ld`), position independence, string API resolution (hashing, import table, `GetProcAddress`), calling conventions (cdecl/stdcall/fastcall/x64), memory allocation (`VirtualAlloc`/`HeapAlloc`/`LocalAlloc`), stack alignment, process execution (`CreateProcess`/`ShellExecute`), and code obfuscation.

---

*End of Technical Reference.*
