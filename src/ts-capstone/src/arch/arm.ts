export interface cs_arm_op {
  vector_index: number; // Vector Index for some vector operands (or -1 if irrelevant)
  shift: {
    type: ARM;
    value: number;
  };
  type: ARM; // operand type
  reg?: number; // register value for REG/SYSREG operand
  imm?: number; // immediate value for C-IMM, P-IMM or IMM operand
  fp?: number; // floating point value for FP operand
  mem?: {
    // base/index/scale/disp value for MEM operand
    base: ARM;
    index: ARM;
    scale: number;
    disp: number;
    lshift: number;
  };
  setend?: ARM; // SETEND instruction's operand type
  subtracted: boolean; // in some instructions, an operand can be subtracted or added to the base register, if TRUE, this operand is subtracted. otherwise, it is added.
  access: number; // How is this operand accessed? (READ, WRITE or READ|WRITE)
  neon_lane: number; // Neon lane index for NEON instructions (or -1 if irrelevant)
}

export enum ARM {
  // ARM shift type
  SFT_INVALID = 0,
  SFT_ASR = 1, // shift with immediate const
  SFT_LSL = 2, // shift with immediate const
  SFT_LSR = 3, // shift with immediate const
  SFT_ROR = 4, // shift with immediate const
  SFT_RRX = 5, // shift with immediate const
  SFT_ASR_REG = 6, // shift with register
  SFT_LSL_REG = 7, // shift with register
  SFT_LSR_REG = 8, // shift with register
  SFT_ROR_REG = 9, // shift with register
  SFT_RRX_REG = 10, // shift with register

  // ARM condition code
  CC_INVALID = 0,
  CC_EQ = 1, // Equal
  CC_NE = 2, // Not equal, or unordered
  CC_HS = 3, // Carry set, >, ==, or unordered
  CC_LO = 4, // Carry clear, Less than
  CC_MI = 5, // Minus, negative, Less than
  CC_PL = 6, // Plus, positive or zero, >, ==, or unordered
  CC_VS = 7, // Overflow, Unordered
  CC_VC = 8, // No overflow, Not unordered
  CC_HI = 9, // Unsigned higher, Greater than, or unordered
  CC_LS = 10, // Unsigned lower or same
  CC_GE = 11, // Greater than or equal
  CC_LT = 12, // Less than, or unordered
  CC_GT = 13, // Greater than
  CC_LE = 14, // Less than or equal, or unordered
  CC_AL = 15, // Always (unconditional)

  // Special registers for MSR
  SYSREG_INVALID = 0,

  // SPSR* registers can be OR combined
  SYSREG_SPSR_C = 1,
  SYSREG_SPSR_X = 2,
  SYSREG_SPSR_S = 4,
  SYSREG_SPSR_F = 8,

  // CPSR* registers can be OR combined
  SYSREG_CPSR_C = 16,
  SYSREG_CPSR_X = 32,
  SYSREG_CPSR_S = 64,
  SYSREG_CPSR_F = 128,

  // independent registers
  SYSREG_APSR = 256,
  SYSREG_APSR_G = 257,
  SYSREG_APSR_NZCVQ = 258,
  SYSREG_APSR_NZCVQG = 259,
  SYSREG_IAPSR = 260,
  SYSREG_IAPSR_G = 261,
  SYSREG_IAPSR_NZCVQG = 262,
  SYSREG_IAPSR_NZCVQ = 263,
  SYSREG_EAPSR = 264,
  SYSREG_EAPSR_G = 265,
  SYSREG_EAPSR_NZCVQG = 266,
  SYSREG_EAPSR_NZCVQ = 267,
  SYSREG_XPSR = 268,
  SYSREG_XPSR_G = 269,
  SYSREG_XPSR_NZCVQG = 270,
  SYSREG_XPSR_NZCVQ = 271,
  SYSREG_IPSR = 272,
  SYSREG_EPSR = 273,
  SYSREG_IEPSR = 274,
  SYSREG_MSP = 275,
  SYSREG_PSP = 276,
  SYSREG_PRIMASK = 277,
  SYSREG_BASEPRI = 278,
  SYSREG_BASEPRI_MAX = 279,
  SYSREG_FAULTMASK = 280,
  SYSREG_CONTROL = 281,
  SYSREG_MSPLIM = 282,
  SYSREG_PSPLIM = 283,
  SYSREG_MSP_NS = 284,
  SYSREG_PSP_NS = 285,
  SYSREG_MSPLIM_NS = 286,
  SYSREG_PSPLIM_NS = 287,
  SYSREG_PRIMASK_NS = 288,
  SYSREG_BASEPRI_NS = 289,
  SYSREG_FAULTMASK_NS = 290,
  SYSREG_CONTROL_NS = 291,
  SYSREG_SP_NS = 292,

  // Banked Registers
  SYSREG_R8_USR = 293,
  SYSREG_R9_USR = 294,
  SYSREG_R10_USR = 295,
  SYSREG_R11_USR = 296,
  SYSREG_R12_USR = 297,
  SYSREG_SP_USR = 298,
  SYSREG_LR_USR = 299,
  SYSREG_R8_FIQ = 300,
  SYSREG_R9_FIQ = 301,
  SYSREG_R10_FIQ = 302,
  SYSREG_R11_FIQ = 303,
  SYSREG_R12_FIQ = 304,
  SYSREG_SP_FIQ = 305,
  SYSREG_LR_FIQ = 306,
  SYSREG_LR_IRQ = 307,
  SYSREG_SP_IRQ = 308,
  SYSREG_LR_SVC = 309,
  SYSREG_SP_SVC = 310,
  SYSREG_LR_ABT = 311,
  SYSREG_SP_ABT = 312,
  SYSREG_LR_UND = 313,
  SYSREG_SP_UND = 314,
  SYSREG_LR_MON = 315,
  SYSREG_SP_MON = 316,
  SYSREG_ELR_HYP = 317,
  SYSREG_SP_HYP = 318,
  SYSREG_SPSR_FIQ = 319,
  SYSREG_SPSR_IRQ = 320,
  SYSREG_SPSR_SVC = 321,
  SYSREG_SPSR_ABT = 322,
  SYSREG_SPSR_UND = 323,
  SYSREG_SPSR_MON = 324,
  SYSREG_SPSR_HYP = 325,

  // The memory barrier constants map directly to the 4-bit encoding of
  MB_INVALID = 0,
  MB_RESERVED_0 = 1,
  MB_OSHLD = 2,
  MB_OSHST = 3,
  MB_OSH = 4,
  MB_RESERVED_4 = 5,
  MB_NSHLD = 6,
  MB_NSHST = 7,
  MB_NSH = 8,
  MB_RESERVED_8 = 9,
  MB_ISHLD = 10,
  MB_ISHST = 11,
  MB_ISH = 12,
  MB_RESERVED_12 = 13,
  MB_LD = 14,
  MB_ST = 15,
  MB_SY = 16,

  // Operand type for instruction's operands
  OP_INVALID = 0, // cs.OP_INVALID (Uninitialized).
  OP_REG = 1, // cs.OP_REG (Register operand).
  OP_IMM = 2, // cs.OP_IMM (Immediate operand).
  OP_MEM = 3, // cs.OP_MEM (Memory operand).
  OP_FP = 4, // cs.OP_FP (Floating-Point operand).
  OP_CIMM = 64, // C-Immediate (coprocessor registers)
  OP_PIMM = 65, // P-Immediate (coprocessor registers)
  OP_SETEND = 66, // operand for SETEND instruction
  OP_SYSREG = 67, // MSR/MRS special register operand

  // Operand type for SETEND instruction
  SETEND_INVALID = 0, // Uninitialized
  SETEND_BE = 1, // BE operand.
  SETEND_LE = 2, // LE operand.

  CPSMODE_INVALID = 0,
  CPSMODE_IE = 2,
  CPSMODE_ID = 3,

  // Operand type for SETEND instruction
  CPSFLAG_INVALID = 0,
  CPSFLAG_F = 1,
  CPSFLAG_I = 2,
  CPSFLAG_A = 4,
  CPSFLAG_NONE = 16, // no flag

  // Data type for elements of vector instructions.
  VECTORDATA_INVALID = 0,

  // Integer type
  VECTORDATA_I8 = 1,
  VECTORDATA_I16 = 2,
  VECTORDATA_I32 = 3,
  VECTORDATA_I64 = 4,

  // Signed integer type
  VECTORDATA_S8 = 5,
  VECTORDATA_S16 = 6,
  VECTORDATA_S32 = 7,
  VECTORDATA_S64 = 8,

  // Unsigned integer type
  VECTORDATA_U8 = 9,
  VECTORDATA_U16 = 10,
  VECTORDATA_U32 = 11,
  VECTORDATA_U64 = 12,

  // Data type for VMUL/VMULL
  VECTORDATA_P8 = 13,

  // Floating type
  VECTORDATA_F16 = 14,
  VECTORDATA_F32 = 15,
  VECTORDATA_F64 = 16,

  // Convert float <-> float
  VECTORDATA_F16F64 = 17, // f16.f64
  VECTORDATA_F64F16 = 18, // f64.f16
  VECTORDATA_F32F16 = 19, // f32.f16
  VECTORDATA_F16F32 = 20, // f16.f32
  VECTORDATA_F64F32 = 21, // f64.f32
  VECTORDATA_F32F64 = 22, // f32.f64

  // Convert integer <-> float
  VECTORDATA_S32F32 = 23, // s32.f32
  VECTORDATA_U32F32 = 24, // u32.f32
  VECTORDATA_F32S32 = 25, // f32.s32
  VECTORDATA_F32U32 = 26, // f32.u32
  VECTORDATA_F64S16 = 27, // f64.s16
  VECTORDATA_F32S16 = 28, // f32.s16
  VECTORDATA_F64S32 = 29, // f64.s32
  VECTORDATA_S16F64 = 30, // s16.f64
  VECTORDATA_S16F32 = 31, // s16.f64
  VECTORDATA_S32F64 = 32, // s32.f64
  VECTORDATA_U16F64 = 33, // u16.f64
  VECTORDATA_U16F32 = 34, // u16.f32
  VECTORDATA_U32F64 = 35, // u32.f64
  VECTORDATA_F64U16 = 36, // f64.u16
  VECTORDATA_F32U16 = 37, // f32.u16
  VECTORDATA_F64U32 = 38, // f64.u32
  VECTORDATA_F16U16 = 39, // f16.u16
  VECTORDATA_U16F16 = 40, // u16.f16
  VECTORDATA_F16U32 = 41, // f16.u32
  VECTORDATA_U32F16 = 42, // u32.f16

  // ARM registers
  REG_INVALID = 0,
  REG_APSR = 1,
  REG_APSR_NZCV = 2,
  REG_CPSR = 3,
  REG_FPEXC = 4,
  REG_FPINST = 5,
  REG_FPSCR = 6,
  REG_FPSCR_NZCV = 7,
  REG_FPSID = 8,
  REG_ITSTATE = 9,
  REG_LR = 10,
  REG_PC = 11,
  REG_SP = 12,
  REG_SPSR = 13,
  REG_D0 = 14,
  REG_D1 = 15,
  REG_D2 = 16,
  REG_D3 = 17,
  REG_D4 = 18,
  REG_D5 = 19,
  REG_D6 = 20,
  REG_D7 = 21,
  REG_D8 = 22,
  REG_D9 = 23,
  REG_D10 = 24,
  REG_D11 = 25,
  REG_D12 = 26,
  REG_D13 = 27,
  REG_D14 = 28,
  REG_D15 = 29,
  REG_D16 = 30,
  REG_D17 = 31,
  REG_D18 = 32,
  REG_D19 = 33,
  REG_D20 = 34,
  REG_D21 = 35,
  REG_D22 = 36,
  REG_D23 = 37,
  REG_D24 = 38,
  REG_D25 = 39,
  REG_D26 = 40,
  REG_D27 = 41,
  REG_D28 = 42,
  REG_D29 = 43,
  REG_D30 = 44,
  REG_D31 = 45,
  REG_FPINST2 = 46,
  REG_MVFR0 = 47,
  REG_MVFR1 = 48,
  REG_MVFR2 = 49,
  REG_Q0 = 50,
  REG_Q1 = 51,
  REG_Q2 = 52,
  REG_Q3 = 53,
  REG_Q4 = 54,
  REG_Q5 = 55,
  REG_Q6 = 56,
  REG_Q7 = 57,
  REG_Q8 = 58,
  REG_Q9 = 59,
  REG_Q10 = 60,
  REG_Q11 = 61,
  REG_Q12 = 62,
  REG_Q13 = 63,
  REG_Q14 = 64,
  REG_Q15 = 65,
  REG_R0 = 66,
  REG_R1 = 67,
  REG_R2 = 68,
  REG_R3 = 69,
  REG_R4 = 70,
  REG_R5 = 71,
  REG_R6 = 72,
  REG_R7 = 73,
  REG_R8 = 74,
  REG_R9 = 75,
  REG_R10 = 76,
  REG_R11 = 77,
  REG_R12 = 78,
  REG_S0 = 79,
  REG_S1 = 80,
  REG_S2 = 81,
  REG_S3 = 82,
  REG_S4 = 83,
  REG_S5 = 84,
  REG_S6 = 85,
  REG_S7 = 86,
  REG_S8 = 87,
  REG_S9 = 88,
  REG_S10 = 89,
  REG_S11 = 90,
  REG_S12 = 91,
  REG_S13 = 92,
  REG_S14 = 93,
  REG_S15 = 94,
  REG_S16 = 95,
  REG_S17 = 96,
  REG_S18 = 97,
  REG_S19 = 98,
  REG_S20 = 99,
  REG_S21 = 100,
  REG_S22 = 101,
  REG_S23 = 102,
  REG_S24 = 103,
  REG_S25 = 104,
  REG_S26 = 105,
  REG_S27 = 106,
  REG_S28 = 107,
  REG_S29 = 108,
  REG_S30 = 109,
  REG_S31 = 110,
  REG_ENDING = 111, // mark the end of the list or registers

  // alias registers
  REG_R13 = REG_SP,
  REG_R14 = REG_LR,
  REG_R15 = REG_PC,
  REG_SB = REG_R9,
  REG_SL = REG_R10,
  REG_FP = REG_R11,
  REG_IP = REG_R12,

  // ARM instruction
  INS_INVALID = 0,
  INS_ADC = 1,
  INS_ADD = 2,
  INS_ADDW = 3,
  INS_ADR = 4,
  INS_AESD = 5,
  INS_AESE = 6,
  INS_AESIMC = 7,
  INS_AESMC = 8,
  INS_AND = 9,
  INS_ASR = 10,
  INS_B = 11,
  INS_BFC = 12,
  INS_BFI = 13,
  INS_BIC = 14,
  INS_BKPT = 15,
  INS_BL = 16,
  INS_BLX = 17,
  INS_BLXNS = 18,
  INS_BX = 19,
  INS_BXJ = 20,
  INS_BXNS = 21,
  INS_CBNZ = 22,
  INS_CBZ = 23,
  INS_CDP = 24,
  INS_CDP2 = 25,
  INS_CLREX = 26,
  INS_CLZ = 27,
  INS_CMN = 28,
  INS_CMP = 29,
  INS_CPS = 30,
  INS_CRC32B = 31,
  INS_CRC32CB = 32,
  INS_CRC32CH = 33,
  INS_CRC32CW = 34,
  INS_CRC32H = 35,
  INS_CRC32W = 36,
  INS_CSDB = 37,
  INS_DBG = 38,
  INS_DCPS1 = 39,
  INS_DCPS2 = 40,
  INS_DCPS3 = 41,
  INS_DFB = 42,
  INS_DMB = 43,
  INS_DSB = 44,
  INS_EOR = 45,
  INS_ERET = 46,
  INS_ESB = 47,
  INS_FADDD = 48,
  INS_FADDS = 49,
  INS_FCMPZD = 50,
  INS_FCMPZS = 51,
  INS_FCONSTD = 52,
  INS_FCONSTS = 53,
  INS_FLDMDBX = 54,
  INS_FLDMIAX = 55,
  INS_FMDHR = 56,
  INS_FMDLR = 57,
  INS_FMSTAT = 58,
  INS_FSTMDBX = 59,
  INS_FSTMIAX = 60,
  INS_FSUBD = 61,
  INS_FSUBS = 62,
  INS_HINT = 63,
  INS_HLT = 64,
  INS_HVC = 65,
  INS_ISB = 66,
  INS_IT = 67,
  INS_LDA = 68,
  INS_LDAB = 69,
  INS_LDAEX = 70,
  INS_LDAEXB = 71,
  INS_LDAEXD = 72,
  INS_LDAEXH = 73,
  INS_LDAH = 74,
  INS_LDC = 75,
  INS_LDC2 = 76,
  INS_LDC2L = 77,
  INS_LDCL = 78,
  INS_LDM = 79,
  INS_LDMDA = 80,
  INS_LDMDB = 81,
  INS_LDMIB = 82,
  INS_LDR = 83,
  INS_LDRB = 84,
  INS_LDRBT = 85,
  INS_LDRD = 86,
  INS_LDREX = 87,
  INS_LDREXB = 88,
  INS_LDREXD = 89,
  INS_LDREXH = 90,
  INS_LDRH = 91,
  INS_LDRHT = 92,
  INS_LDRSB = 93,
  INS_LDRSBT = 94,
  INS_LDRSH = 95,
  INS_LDRSHT = 96,
  INS_LDRT = 97,
  INS_LSL = 98,
  INS_LSR = 99,
  INS_MCR = 100,
  INS_MCR2 = 101,
  INS_MCRR = 102,
  INS_MCRR2 = 103,
  INS_MLA = 104,
  INS_MLS = 105,
  INS_MOV = 106,
  INS_MOVS = 107,
  INS_MOVT = 108,
  INS_MOVW = 109,
  INS_MRC = 110,
  INS_MRC2 = 111,
  INS_MRRC = 112,
  INS_MRRC2 = 113,
  INS_MRS = 114,
  INS_MSR = 115,
  INS_MUL = 116,
  INS_MVN = 117,
  INS_NEG = 118,
  INS_NOP = 119,
  INS_ORN = 120,
  INS_ORR = 121,
  INS_PKHBT = 122,
  INS_PKHTB = 123,
  INS_PLD = 124,
  INS_PLDW = 125,
  INS_PLI = 126,
  INS_POP = 127,
  INS_PUSH = 128,
  INS_QADD = 129,
  INS_QADD16 = 130,
  INS_QADD8 = 131,
  INS_QASX = 132,
  INS_QDADD = 133,
  INS_QDSUB = 134,
  INS_QSAX = 135,
  INS_QSUB = 136,
  INS_QSUB16 = 137,
  INS_QSUB8 = 138,
  INS_RBIT = 139,
  INS_REV = 140,
  INS_REV16 = 141,
  INS_REVSH = 142,
  INS_RFEDA = 143,
  INS_RFEDB = 144,
  INS_RFEIA = 145,
  INS_RFEIB = 146,
  INS_ROR = 147,
  INS_RRX = 148,
  INS_RSB = 149,
  INS_RSC = 150,
  INS_SADD16 = 151,
  INS_SADD8 = 152,
  INS_SASX = 153,
  INS_SBC = 154,
  INS_SBFX = 155,
  INS_SDIV = 156,
  INS_SEL = 157,
  INS_SETEND = 158,
  INS_SETPAN = 159,
  INS_SEV = 160,
  INS_SEVL = 161,
  INS_SG = 162,
  INS_SHA1C = 163,
  INS_SHA1H = 164,
  INS_SHA1M = 165,
  INS_SHA1P = 166,
  INS_SHA1SU0 = 167,
  INS_SHA1SU1 = 168,
  INS_SHA256H = 169,
  INS_SHA256H2 = 170,
  INS_SHA256SU0 = 171,
  INS_SHA256SU1 = 172,
  INS_SHADD16 = 173,
  INS_SHADD8 = 174,
  INS_SHASX = 175,
  INS_SHSAX = 176,
  INS_SHSUB16 = 177,
  INS_SHSUB8 = 178,
  INS_SMC = 179,
  INS_SMLABB = 180,
  INS_SMLABT = 181,
  INS_SMLAD = 182,
  INS_SMLADX = 183,
  INS_SMLAL = 184,
  INS_SMLALBB = 185,
  INS_SMLALBT = 186,
  INS_SMLALD = 187,
  INS_SMLALDX = 188,
  INS_SMLALTB = 189,
  INS_SMLALTT = 190,
  INS_SMLATB = 191,
  INS_SMLATT = 192,
  INS_SMLAWB = 193,
  INS_SMLAWT = 194,
  INS_SMLSD = 195,
  INS_SMLSDX = 196,
  INS_SMLSLD = 197,
  INS_SMLSLDX = 198,
  INS_SMMLA = 199,
  INS_SMMLAR = 200,
  INS_SMMLS = 201,
  INS_SMMLSR = 202,
  INS_SMMUL = 203,
  INS_SMMULR = 204,
  INS_SMUAD = 205,
  INS_SMUADX = 206,
  INS_SMULBB = 207,
  INS_SMULBT = 208,
  INS_SMULL = 209,
  INS_SMULTB = 210,
  INS_SMULTT = 211,
  INS_SMULWB = 212,
  INS_SMULWT = 213,
  INS_SMUSD = 214,
  INS_SMUSDX = 215,
  INS_SRSDA = 216,
  INS_SRSDB = 217,
  INS_SRSIA = 218,
  INS_SRSIB = 219,
  INS_SSAT = 220,
  INS_SSAT16 = 221,
  INS_SSAX = 222,
  INS_SSUB16 = 223,
  INS_SSUB8 = 224,
  INS_STC = 225,
  INS_STC2 = 226,
  INS_STC2L = 227,
  INS_STCL = 228,
  INS_STL = 229,
  INS_STLB = 230,
  INS_STLEX = 231,
  INS_STLEXB = 232,
  INS_STLEXD = 233,
  INS_STLEXH = 234,
  INS_STLH = 235,
  INS_STM = 236,
  INS_STMDA = 237,
  INS_STMDB = 238,
  INS_STMIB = 239,
  INS_STR = 240,
  INS_STRB = 241,
  INS_STRBT = 242,
  INS_STRD = 243,
  INS_STREX = 244,
  INS_STREXB = 245,
  INS_STREXD = 246,
  INS_STREXH = 247,
  INS_STRH = 248,
  INS_STRHT = 249,
  INS_STRT = 250,
  INS_SUB = 251,
  INS_SUBS = 252,
  INS_SUBW = 253,
  INS_SVC = 254,
  INS_SWP = 255,
  INS_SWPB = 256,
  INS_SXTAB = 257,
  INS_SXTAB16 = 258,
  INS_SXTAH = 259,
  INS_SXTB = 260,
  INS_SXTB16 = 261,
  INS_SXTH = 262,
  INS_TBB = 263,
  INS_TBH = 264,
  INS_TEQ = 265,
  INS_TRAP = 266,
  INS_TSB = 267,
  INS_TST = 268,
  INS_TT = 269,
  INS_TTA = 270,
  INS_TTAT = 271,
  INS_TTT = 272,
  INS_UADD16 = 273,
  INS_UADD8 = 274,
  INS_UASX = 275,
  INS_UBFX = 276,
  INS_UDF = 277,
  INS_UDIV = 278,
  INS_UHADD16 = 279,
  INS_UHADD8 = 280,
  INS_UHASX = 281,
  INS_UHSAX = 282,
  INS_UHSUB16 = 283,
  INS_UHSUB8 = 284,
  INS_UMAAL = 285,
  INS_UMLAL = 286,
  INS_UMULL = 287,
  INS_UQADD16 = 288,
  INS_UQADD8 = 289,
  INS_UQASX = 290,
  INS_UQSAX = 291,
  INS_UQSUB16 = 292,
  INS_UQSUB8 = 293,
  INS_USAD8 = 294,
  INS_USADA8 = 295,
  INS_USAT = 296,
  INS_USAT16 = 297,
  INS_USAX = 298,
  INS_USUB16 = 299,
  INS_USUB8 = 300,
  INS_UXTAB = 301,
  INS_UXTAB16 = 302,
  INS_UXTAH = 303,
  INS_UXTB = 304,
  INS_UXTB16 = 305,
  INS_UXTH = 306,
  INS_VABA = 307,
  INS_VABAL = 308,
  INS_VABD = 309,
  INS_VABDL = 310,
  INS_VABS = 311,
  INS_VACGE = 312,
  INS_VACGT = 313,
  INS_VACLE = 314,
  INS_VACLT = 315,
  INS_VADD = 316,
  INS_VADDHN = 317,
  INS_VADDL = 318,
  INS_VADDW = 319,
  INS_VAND = 320,
  INS_VBIC = 321,
  INS_VBIF = 322,
  INS_VBIT = 323,
  INS_VBSL = 324,
  INS_VCADD = 325,
  INS_VCEQ = 326,
  INS_VCGE = 327,
  INS_VCGT = 328,
  INS_VCLE = 329,
  INS_VCLS = 330,
  INS_VCLT = 331,
  INS_VCLZ = 332,
  INS_VCMLA = 333,
  INS_VCMP = 334,
  INS_VCMPE = 335,
  INS_VCNT = 336,
  INS_VCVT = 337,
  INS_VCVTA = 338,
  INS_VCVTB = 339,
  INS_VCVTM = 340,
  INS_VCVTN = 341,
  INS_VCVTP = 342,
  INS_VCVTR = 343,
  INS_VCVTT = 344,
  INS_VDIV = 345,
  INS_VDUP = 346,
  INS_VEOR = 347,
  INS_VEXT = 348,
  INS_VFMA = 349,
  INS_VFMS = 350,
  INS_VFNMA = 351,
  INS_VFNMS = 352,
  INS_VHADD = 353,
  INS_VHSUB = 354,
  INS_VINS = 355,
  INS_VJCVT = 356,
  INS_VLD1 = 357,
  INS_VLD2 = 358,
  INS_VLD3 = 359,
  INS_VLD4 = 360,
  INS_VLDMDB = 361,
  INS_VLDMIA = 362,
  INS_VLDR = 363,
  INS_VLLDM = 364,
  INS_VLSTM = 365,
  INS_VMAX = 366,
  INS_VMAXNM = 367,
  INS_VMIN = 368,
  INS_VMINNM = 369,
  INS_VMLA = 370,
  INS_VMLAL = 371,
  INS_VMLS = 372,
  INS_VMLSL = 373,
  INS_VMOV = 374,
  INS_VMOVL = 375,
  INS_VMOVN = 376,
  INS_VMOVX = 377,
  INS_VMRS = 378,
  INS_VMSR = 379,
  INS_VMUL = 380,
  INS_VMULL = 381,
  INS_VMVN = 382,
  INS_VNEG = 383,
  INS_VNMLA = 384,
  INS_VNMLS = 385,
  INS_VNMUL = 386,
  INS_VORN = 387,
  INS_VORR = 388,
  INS_VPADAL = 389,
  INS_VPADD = 390,
  INS_VPADDL = 391,
  INS_VPMAX = 392,
  INS_VPMIN = 393,
  INS_VPOP = 394,
  INS_VPUSH = 395,
  INS_VQABS = 396,
  INS_VQADD = 397,
  INS_VQDMLAL = 398,
  INS_VQDMLSL = 399,
  INS_VQDMULH = 400,
  INS_VQDMULL = 401,
  INS_VQMOVN = 402,
  INS_VQMOVUN = 403,
  INS_VQNEG = 404,
  INS_VQRDMLAH = 405,
  INS_VQRDMLSH = 406,
  INS_VQRDMULH = 407,
  INS_VQRSHL = 408,
  INS_VQRSHRN = 409,
  INS_VQRSHRUN = 410,
  INS_VQSHL = 411,
  INS_VQSHLU = 412,
  INS_VQSHRN = 413,
  INS_VQSHRUN = 414,
  INS_VQSUB = 415,
  INS_VRADDHN = 416,
  INS_VRECPE = 417,
  INS_VRECPS = 418,
  INS_VREV16 = 419,
  INS_VREV32 = 420,
  INS_VREV64 = 421,
  INS_VRHADD = 422,
  INS_VRINTA = 423,
  INS_VRINTM = 424,
  INS_VRINTN = 425,
  INS_VRINTP = 426,
  INS_VRINTR = 427,
  INS_VRINTX = 428,
  INS_VRINTZ = 429,
  INS_VRSHL = 430,
  INS_VRSHR = 431,
  INS_VRSHRN = 432,
  INS_VRSQRTE = 433,
  INS_VRSQRTS = 434,
  INS_VRSRA = 435,
  INS_VRSUBHN = 436,
  INS_VSDOT = 437,
  INS_VSELEQ = 438,
  INS_VSELGE = 439,
  INS_VSELGT = 440,
  INS_VSELVS = 441,
  INS_VSHL = 442,
  INS_VSHLL = 443,
  INS_VSHR = 444,
  INS_VSHRN = 445,
  INS_VSLI = 446,
  INS_VSQRT = 447,
  INS_VSRA = 448,
  INS_VSRI = 449,
  INS_VST1 = 450,
  INS_VST2 = 451,
  INS_VST3 = 452,
  INS_VST4 = 453,
  INS_VSTMDB = 454,
  INS_VSTMIA = 455,
  INS_VSTR = 456,
  INS_VSUB = 457,
  INS_VSUBHN = 458,
  INS_VSUBL = 459,
  INS_VSUBW = 460,
  INS_VSWP = 461,
  INS_VTBL = 462,
  INS_VTBX = 463,
  INS_VTRN = 464,
  INS_VTST = 465,
  INS_VUDOT = 466,
  INS_VUZP = 467,
  INS_VZIP = 468,
  INS_WFE = 469,
  INS_WFI = 470,
  INS_YIELD = 471,
  INS_ENDING = 472, // mark the end of the list of instructions

  // Group of ARM instructions
  GRP_INVALID = 0, // cs.GRP_INVALID

  // Generic groups
  // all jump instructions (conditional+direct+indirect jumps)
  GRP_JUMP = 1, // cs.GRP_JUMP
  GRP_CALL = 2, // cs.GRP_CALL
  GRP_INT = 4, // cs.GRP_INT
  GRP_PRIVILEGE = 6, // cs.GRP_PRIVILEGE
  GRP_BRANCH_RELATIVE = 7, // cs.GRP_BRANCH_RELATIVE

  // Architecture-specific groups
  GRP_CRYPTO = 128,
  GRP_DATABARRIER = 129,
  GRP_DIVIDE = 130,
  GRP_FPARMV8 = 131,
  GRP_MULTPRO = 132,
  GRP_NEON = 133,
  GRP_T2EXTRACTPACK = 134,
  GRP_THUMB2DSP = 135,
  GRP_TRUSTZONE = 136,
  GRP_V4T = 137,
  GRP_V5T = 138,
  GRP_V5TE = 139,
  GRP_V6 = 140,
  GRP_V6T2 = 141,
  GRP_V7 = 142,
  GRP_V8 = 143,
  GRP_VFP2 = 144,
  GRP_VFP3 = 145,
  GRP_VFP4 = 146,
  GRP_ARM = 147,
  GRP_MCLASS = 148,
  GRP_NOTMCLASS = 149,
  GRP_THUMB = 150,
  GRP_THUMB1ONLY = 151,
  GRP_THUMB2 = 152,
  GRP_PREV8 = 153,
  GRP_FPVMLX = 154,
  GRP_MULOPS = 155,
  GRP_CRC = 156,
  GRP_DPVFP = 157,
  GRP_V6M = 158,
  GRP_VIRTUALIZATION = 159,
  GRP_ENDING = 160,
}

export class cs_arm {
  public usermode: boolean; // User-mode registers to be loaded (for LDM/STM instructions)
  public vector_size: number; // Scalar size for vector instructions
  public vector_data: ARM; // Data type for elements of vector instructions
  public cc: ARM; // CPS mode for CPS instruction
  public cps_mode: ARM; // CPS mode for CPS instruction
  public cps_flag: ARM; // conditional code for this insn
  public update_flags: boolean; // does this insn update flags?
  public writeback: boolean; // does this insn write-back?
  public post_index: boolean; // only set if writeback is 'True', if 'False' pre-index, otherwise post.
  public mem_barrier: ARM; // Option for some memory barrier instructions
  public op_count: number; // Number of operands of this instruction, or 0 when instruction has no operand.
  public operands: cs_arm_op[]; // operands for this instruction.

  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.usermode = Memory.read(arch_info_ptr, 'bool');
    this.vector_size = Memory.read(arch_info_ptr + 4, 'i32');
    this.vector_data = Memory.read(arch_info_ptr + 9, 'i32');
    this.cps_mode = Memory.read(arch_info_ptr + 12, 'i32');
    this.cps_flag = Memory.read(arch_info_ptr + 16, 'i32');
    this.cc = Memory.read(arch_info_ptr + 20, 'i32');
    this.update_flags = Memory.read(arch_info_ptr + 24, 'bool');
    this.writeback = Memory.read(arch_info_ptr + 25, 'bool');
    this.post_index = Memory.read(arch_info_ptr + 26, 'bool');
    this.mem_barrier = Memory.read(arch_info_ptr + 28, 'i32');
    this.op_count = Memory.read(arch_info_ptr + 32, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_arm_op = {} as cs_arm_op;
      const op_ptr: number = arch_info_ptr + 40 + i * 48;
      op.vector_index = Memory.read(op_ptr + 0, 'i32');
      op.shift = {
        type: Memory.read(op_ptr + 4, 'i32'),
        value: Memory.read(op_ptr + 8, 'u32'),
      };
      op.subtracted = Memory.read(op_ptr + 40, 'bool');
      op.access = Memory.read(op_ptr + 41, 'ubyte');
      op.neon_lane = Memory.read(op_ptr + 42, 'i8');
      op.type = Memory.read(op_ptr + 12, 'i32');
      switch (op.type) {
        case ARM.OP_SYSREG:
        case ARM.OP_REG:
          op.reg = Memory.read(op_ptr + 16, 'i32');
          break;
        case ARM.OP_IMM:
        case ARM.OP_PIMM:
          op.imm = Memory.read(op_ptr + 16, 'i32');
          break;
        case ARM.OP_FP:
          op.fp = Memory.read(op_ptr + 16, 'double');
          break;
        case ARM.OP_SETEND:
          op.setend = Memory.read(op_ptr + 16, 'i32');
          break;
        case ARM.OP_MEM:
          op.mem = {
            base: Memory.read(op_ptr + 16, 'i32'),
            index: Memory.read(op_ptr + 20, 'i32'),
            scale: Memory.read(op_ptr + 24, 'i32'),
            disp: Memory.read(op_ptr + 28, 'i32'),
            lshift: Memory.read(op_ptr + 32, 'i32'),
          };
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
