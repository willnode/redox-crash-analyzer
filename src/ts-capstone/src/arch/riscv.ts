export interface cs_riscv_op {
  type?: RISCV; // operand type
  reg?: RISCV; // register value for REG operand
  imm?: number; // immediate value for IMM operand
  mem?: {
    // base/disp value for MEM operand
    base: number; // base register
    disp: number; // displacement/offset value
  };
}

export enum RISCV {
  // Operand type for instruction's operands
  OP_INVALID = 0,
  OP_REG = 1,
  OP_IMM = 2,
  OP_MEM = 3,

  // RISCV registers
  REG_INVALID = 0,

  // General purpose registers
  REG_X0 = 1,
  // REG_ZERO = RISCV_REG_X0
  REG_X1 = 2,
  // REG_RA = RISCV_REG_X1
  REG_X2 = 3,
  // REG_SP = RISCV_REG_X2
  REG_X3 = 4,
  // REG_GP = RISCV_REG_X3
  REG_X4 = 5,
  // REG_TP = RISCV_REG_X4
  REG_X5 = 6,
  // REG_T0 = RISCV_REG_X5
  REG_X6 = 7,
  // REG_T1 = RISCV_REG_X6
  REG_X7 = 8,
  // REG_T2 = RISCV_REG_X7
  REG_X8 = 9,
  // REG_S0 = RISCV_REG_X8
  // REG_FP = RISCV_REG_X8
  REG_X9 = 10,
  // REG_S1 = RISCV_REG_X9
  REG_X10 = 11,
  // REG_A0 = RISCV_REG_X10
  REG_X11 = 12,
  // REG_A1 = RISCV_REG_X11
  REG_X12 = 13,
  // REG_A2 = RISCV_REG_X12
  REG_X13 = 14,
  // REG_A3 = RISCV_REG_X13
  REG_X14 = 15,
  // REG_A4 = RISCV_REG_X14
  REG_X15 = 16,
  // REG_A5 = RISCV_REG_X15
  REG_X16 = 17,
  // REG_A6 = RISCV_REG_X16
  REG_X17 = 18,
  // REG_A7 = RISCV_REG_X17
  REG_X18 = 19,
  // REG_S2 = RISCV_REG_X18
  REG_X19 = 20,
  // REG_S3 = RISCV_REG_X19
  REG_X20 = 21,
  // REG_S4 = RISCV_REG_X20
  REG_X21 = 22,
  // REG_S5 = RISCV_REG_X21
  REG_X22 = 23,
  // REG_S6 = RISCV_REG_X22
  REG_X23 = 24,
  // REG_S7 = RISCV_REG_X23
  REG_X24 = 25,
  // REG_S8 = RISCV_REG_X24
  REG_X25 = 26,
  // REG_S9 = RISCV_REG_X25
  REG_X26 = 27,
  // REG_S10 = RISCV_REG_X26
  REG_X27 = 28,
  // REG_S11 = RISCV_REG_X27
  REG_X28 = 29,
  // REG_T3 = RISCV_REG_X28
  REG_X29 = 30,
  // REG_T4 = RISCV_REG_X29
  REG_X30 = 31,
  // REG_T5 = RISCV_REG_X30
  REG_X31 = 32,
  // REG_T6 = RISCV_REG_X31

  // Floating-point registers
  REG_F0_32 = 33,
  REG_F0_64 = 34,
  REG_F1_32 = 35,
  REG_F1_64 = 36,
  REG_F2_32 = 37,
  REG_F2_64 = 38,
  REG_F3_32 = 39,
  REG_F3_64 = 40,
  REG_F4_32 = 41,
  REG_F4_64 = 42,
  REG_F5_32 = 43,
  REG_F5_64 = 44,
  REG_F6_32 = 45,
  REG_F6_64 = 46,
  REG_F7_32 = 47,
  REG_F7_64 = 48,
  REG_F8_32 = 49,
  REG_F8_64 = 50,
  REG_F9_32 = 51,
  REG_F9_64 = 52,
  REG_F10_32 = 53,
  REG_F10_64 = 54,
  REG_F11_32 = 55,
  REG_F11_64 = 56,
  REG_F12_32 = 57,
  REG_F12_64 = 58,
  REG_F13_32 = 59,
  REG_F13_64 = 60,
  REG_F14_32 = 61,
  REG_F14_64 = 62,
  REG_F15_32 = 63,
  REG_F15_64 = 64,
  REG_F16_32 = 65,
  REG_F16_64 = 66,
  REG_F17_32 = 67,
  REG_F17_64 = 68,
  REG_F18_32 = 69,
  REG_F18_64 = 70,
  REG_F19_32 = 71,
  REG_F19_64 = 72,
  REG_F20_32 = 73,
  REG_F20_64 = 74,
  REG_F21_32 = 75,
  REG_F21_64 = 76,
  REG_F22_32 = 77,
  REG_F22_64 = 78,
  REG_F23_32 = 79,
  REG_F23_64 = 80,
  REG_F24_32 = 81,
  REG_F24_64 = 82,
  REG_F25_32 = 83,
  REG_F25_64 = 84,
  REG_F26_32 = 85,
  REG_F26_64 = 86,
  REG_F27_32 = 87,
  REG_F27_64 = 88,
  REG_F28_32 = 89,
  REG_F28_64 = 90,
  REG_F29_32 = 91,
  REG_F29_64 = 92,
  REG_F30_32 = 93,
  REG_F30_64 = 94,
  REG_F31_32 = 95,
  REG_F31_64 = 96,
  REG_ENDING = 97,

  // RISCV instruction
  INS_INVALID = 0,
  INS_ADD = 1,
  INS_ADDI = 2,
  INS_ADDIW = 3,
  INS_ADDW = 4,
  INS_AMOADD_D = 5,
  INS_AMOADD_D_AQ = 6,
  INS_AMOADD_D_AQ_RL = 7,
  INS_AMOADD_D_RL = 8,
  INS_AMOADD_W = 9,
  INS_AMOADD_W_AQ = 10,
  INS_AMOADD_W_AQ_RL = 11,
  INS_AMOADD_W_RL = 12,
  INS_AMOAND_D = 13,
  INS_AMOAND_D_AQ = 14,
  INS_AMOAND_D_AQ_RL = 15,
  INS_AMOAND_D_RL = 16,
  INS_AMOAND_W = 17,
  INS_AMOAND_W_AQ = 18,
  INS_AMOAND_W_AQ_RL = 19,
  INS_AMOAND_W_RL = 20,
  INS_AMOMAXU_D = 21,
  INS_AMOMAXU_D_AQ = 22,
  INS_AMOMAXU_D_AQ_RL = 23,
  INS_AMOMAXU_D_RL = 24,
  INS_AMOMAXU_W = 25,
  INS_AMOMAXU_W_AQ = 26,
  INS_AMOMAXU_W_AQ_RL = 27,
  INS_AMOMAXU_W_RL = 28,
  INS_AMOMAX_D = 29,
  INS_AMOMAX_D_AQ = 30,
  INS_AMOMAX_D_AQ_RL = 31,
  INS_AMOMAX_D_RL = 32,
  INS_AMOMAX_W = 33,
  INS_AMOMAX_W_AQ = 34,
  INS_AMOMAX_W_AQ_RL = 35,
  INS_AMOMAX_W_RL = 36,
  INS_AMOMINU_D = 37,
  INS_AMOMINU_D_AQ = 38,
  INS_AMOMINU_D_AQ_RL = 39,
  INS_AMOMINU_D_RL = 40,
  INS_AMOMINU_W = 41,
  INS_AMOMINU_W_AQ = 42,
  INS_AMOMINU_W_AQ_RL = 43,
  INS_AMOMINU_W_RL = 44,
  INS_AMOMIN_D = 45,
  INS_AMOMIN_D_AQ = 46,
  INS_AMOMIN_D_AQ_RL = 47,
  INS_AMOMIN_D_RL = 48,
  INS_AMOMIN_W = 49,
  INS_AMOMIN_W_AQ = 50,
  INS_AMOMIN_W_AQ_RL = 51,
  INS_AMOMIN_W_RL = 52,
  INS_AMOOR_D = 53,
  INS_AMOOR_D_AQ = 54,
  INS_AMOOR_D_AQ_RL = 55,
  INS_AMOOR_D_RL = 56,
  INS_AMOOR_W = 57,
  INS_AMOOR_W_AQ = 58,
  INS_AMOOR_W_AQ_RL = 59,
  INS_AMOOR_W_RL = 60,
  INS_AMOSWAP_D = 61,
  INS_AMOSWAP_D_AQ = 62,
  INS_AMOSWAP_D_AQ_RL = 63,
  INS_AMOSWAP_D_RL = 64,
  INS_AMOSWAP_W = 65,
  INS_AMOSWAP_W_AQ = 66,
  INS_AMOSWAP_W_AQ_RL = 67,
  INS_AMOSWAP_W_RL = 68,
  INS_AMOXOR_D = 69,
  INS_AMOXOR_D_AQ = 70,
  INS_AMOXOR_D_AQ_RL = 71,
  INS_AMOXOR_D_RL = 72,
  INS_AMOXOR_W = 73,
  INS_AMOXOR_W_AQ = 74,
  INS_AMOXOR_W_AQ_RL = 75,
  INS_AMOXOR_W_RL = 76,
  INS_AND = 77,
  INS_ANDI = 78,
  INS_AUIPC = 79,
  INS_BEQ = 80,
  INS_BGE = 81,
  INS_BGEU = 82,
  INS_BLT = 83,
  INS_BLTU = 84,
  INS_BNE = 85,
  INS_CSRRC = 86,
  INS_CSRRCI = 87,
  INS_CSRRS = 88,
  INS_CSRRSI = 89,
  INS_CSRRW = 90,
  INS_CSRRWI = 91,
  INS_C_ADD = 92,
  INS_C_ADDI = 93,
  INS_C_ADDI16SP = 94,
  INS_C_ADDI4SPN = 95,
  INS_C_ADDIW = 96,
  INS_C_ADDW = 97,
  INS_C_AND = 98,
  INS_C_ANDI = 99,
  INS_C_BEQZ = 100,
  INS_C_BNEZ = 101,
  INS_C_EBREAK = 102,
  INS_C_FLD = 103,
  INS_C_FLDSP = 104,
  INS_C_FLW = 105,
  INS_C_FLWSP = 106,
  INS_C_FSD = 107,
  INS_C_FSDSP = 108,
  INS_C_FSW = 109,
  INS_C_FSWSP = 110,
  INS_C_J = 111,
  INS_C_JAL = 112,
  INS_C_JALR = 113,
  INS_C_JR = 114,
  INS_C_LD = 115,
  INS_C_LDSP = 116,
  INS_C_LI = 117,
  INS_C_LUI = 118,
  INS_C_LW = 119,
  INS_C_LWSP = 120,
  INS_C_MV = 121,
  INS_C_NOP = 122,
  INS_C_OR = 123,
  INS_C_SD = 124,
  INS_C_SDSP = 125,
  INS_C_SLLI = 126,
  INS_C_SRAI = 127,
  INS_C_SRLI = 128,
  INS_C_SUB = 129,
  INS_C_SUBW = 130,
  INS_C_SW = 131,
  INS_C_SWSP = 132,
  INS_C_UNIMP = 133,
  INS_C_XOR = 134,
  INS_DIV = 135,
  INS_DIVU = 136,
  INS_DIVUW = 137,
  INS_DIVW = 138,
  INS_EBREAK = 139,
  INS_ECALL = 140,
  INS_FADD_D = 141,
  INS_FADD_S = 142,
  INS_FCLASS_D = 143,
  INS_FCLASS_S = 144,
  INS_FCVT_D_L = 145,
  INS_FCVT_D_LU = 146,
  INS_FCVT_D_S = 147,
  INS_FCVT_D_W = 148,
  INS_FCVT_D_WU = 149,
  INS_FCVT_LU_D = 150,
  INS_FCVT_LU_S = 151,
  INS_FCVT_L_D = 152,
  INS_FCVT_L_S = 153,
  INS_FCVT_S_D = 154,
  INS_FCVT_S_L = 155,
  INS_FCVT_S_LU = 156,
  INS_FCVT_S_W = 157,
  INS_FCVT_S_WU = 158,
  INS_FCVT_WU_D = 159,
  INS_FCVT_WU_S = 160,
  INS_FCVT_W_D = 161,
  INS_FCVT_W_S = 162,
  INS_FDIV_D = 163,
  INS_FDIV_S = 164,
  INS_FENCE = 165,
  INS_FENCE_I = 166,
  INS_FENCE_TSO = 167,
  INS_FEQ_D = 168,
  INS_FEQ_S = 169,
  INS_FLD = 170,
  INS_FLE_D = 171,
  INS_FLE_S = 172,
  INS_FLT_D = 173,
  INS_FLT_S = 174,
  INS_FLW = 175,
  INS_FMADD_D = 176,
  INS_FMADD_S = 177,
  INS_FMAX_D = 178,
  INS_FMAX_S = 179,
  INS_FMIN_D = 180,
  INS_FMIN_S = 181,
  INS_FMSUB_D = 182,
  INS_FMSUB_S = 183,
  INS_FMUL_D = 184,
  INS_FMUL_S = 185,
  INS_FMV_D_X = 186,
  INS_FMV_W_X = 187,
  INS_FMV_X_D = 188,
  INS_FMV_X_W = 189,
  INS_FNMADD_D = 190,
  INS_FNMADD_S = 191,
  INS_FNMSUB_D = 192,
  INS_FNMSUB_S = 193,
  INS_FSD = 194,
  INS_FSGNJN_D = 195,
  INS_FSGNJN_S = 196,
  INS_FSGNJX_D = 197,
  INS_FSGNJX_S = 198,
  INS_FSGNJ_D = 199,
  INS_FSGNJ_S = 200,
  INS_FSQRT_D = 201,
  INS_FSQRT_S = 202,
  INS_FSUB_D = 203,
  INS_FSUB_S = 204,
  INS_FSW = 205,
  INS_JAL = 206,
  INS_JALR = 207,
  INS_LB = 208,
  INS_LBU = 209,
  INS_LD = 210,
  INS_LH = 211,
  INS_LHU = 212,
  INS_LR_D = 213,
  INS_LR_D_AQ = 214,
  INS_LR_D_AQ_RL = 215,
  INS_LR_D_RL = 216,
  INS_LR_W = 217,
  INS_LR_W_AQ = 218,
  INS_LR_W_AQ_RL = 219,
  INS_LR_W_RL = 220,
  INS_LUI = 221,
  INS_LW = 222,
  INS_LWU = 223,
  INS_MRET = 224,
  INS_MUL = 225,
  INS_MULH = 226,
  INS_MULHSU = 227,
  INS_MULHU = 228,
  INS_MULW = 229,
  INS_OR = 230,
  INS_ORI = 231,
  INS_REM = 232,
  INS_REMU = 233,
  INS_REMUW = 234,
  INS_REMW = 235,
  INS_SB = 236,
  INS_SC_D = 237,
  INS_SC_D_AQ = 238,
  INS_SC_D_AQ_RL = 239,
  INS_SC_D_RL = 240,
  INS_SC_W = 241,
  INS_SC_W_AQ = 242,
  INS_SC_W_AQ_RL = 243,
  INS_SC_W_RL = 244,
  INS_SD = 245,
  INS_SFENCE_VMA = 246,
  INS_SH = 247,
  INS_SLL = 248,
  INS_SLLI = 249,
  INS_SLLIW = 250,
  INS_SLLW = 251,
  INS_SLT = 252,
  INS_SLTI = 253,
  INS_SLTIU = 254,
  INS_SLTU = 255,
  INS_SRA = 256,
  INS_SRAI = 257,
  INS_SRAIW = 258,
  INS_SRAW = 259,
  INS_SRET = 260,
  INS_SRL = 261,
  INS_SRLI = 262,
  INS_SRLIW = 263,
  INS_SRLW = 264,
  INS_SUB = 265,
  INS_SUBW = 266,
  INS_SW = 267,
  INS_UNIMP = 268,
  INS_URET = 269,
  INS_WFI = 270,
  INS_XOR = 271,
  INS_XORI = 272,
  INS_ENDING = 273,

  // Group of RISCV instructions
  GRP_INVALID = 0, // cs.GRP_INVALID

  // Generic groups
  // all jump instructions (conditional+direct+indirect jumps)
  GRP_JUMP = 1, // cs.GRP_JUMP
  // all call instructions
  GRP_CALL = 2, // cs.GRP_CALL
  // all return instructions
  GRP_RET = 3, // cs.GRP_RET
  // all interrupt instructions (int+syscall)
  GRP_INT = 4, // cs.GRP_INT
  // all interrupt return instructions
  GRP_IRET = 5, // cs.GRP_IRET
  // all privileged instructions
  GRP_PRIVILEGE = 6, // cs.GRP_PRIVILEGE
  // all relative branching instructions
  GRP_BRANCH_RELATIVE = 7, // cs.GRP_BRANCH_RELATIVE

  // Architecture-specific groups
  GRP_ISRV32 = 128,
  GRP_ISRV64 = 129,
  GRP_HASSTDEXTA = 130,
  GRP_HASSTDEXTC = 131,
  GRP_HASSTDEXTD = 132,
  GRP_HASSTDEXTF = 133,
  GRP_HASSTDEXTM = 134,
  GRP_ISRVA = 135,
  GRP_ISRVC = 136,
  GRP_ISRVD = 137,
  GRP_ISRVCD = 138,
  GRP_ISRVF = 139,
  GRP_ISRV32C = 140,
  GRP_ISRV32CF = 141,
  GRP_ISRVM = 142,
  GRP_ISRV64A = 143,
  GRP_ISRV64C = 144,
  GRP_ISRV64D = 145,
  GRP_ISRV64F = 146,
  GRP_ISRV64M = 147,
  GRP_ENDING = 148,
}

export class cs_riscv {
  public need_effective_addr: boolean; // Does this instruction need effective address or not.
  public op_count: number; // Number of operands of this instruction, or 0 when instruction has no operand.
  public operands: cs_riscv_op[]; // operands for this instruction.

  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.need_effective_addr = Memory.read(arch_info_ptr + 0, 'bool');
    this.op_count = Memory.read(arch_info_ptr + 1, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_riscv_op = {} as cs_riscv_op;
      const op_ptr: number = arch_info_ptr + 8 + i * 24;
      op.type = Memory.read(op_ptr + 0, 'i32');
      switch (op.type) {
        case RISCV.OP_REG:
          op.reg = Memory.read(op_ptr + 8, 'u32');
          break;
        case RISCV.OP_IMM:
          op.imm = Memory.read(op_ptr + 8, 'i32');
          break;
        case RISCV.OP_MEM:
          op.mem = {
            base: Memory.read(op_ptr + 8, 'u32'),
            disp: Memory.read(op_ptr + 16, 'i64'),
          };
          break;
      }
      this.operands[i] = op;
    }

    return this;
  }
}
