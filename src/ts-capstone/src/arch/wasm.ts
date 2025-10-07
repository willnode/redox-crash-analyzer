export interface cs_wasm_op {
  type: WASM;
  size: number;
  int7?: number;
  varuint32?: number;
  varuint64?: number;
  uint32?: number;
  uint64?: number;
  immediate?: number[];
  brtable?: {
    length: number;
    address: number;
    default_target: number;
  };
}

export enum WASM {
  // WASM instruction
  OP_INVALID = 0,
  OP_NONE = 1,
  OP_INT7 = 2,
  OP_VARUINT32 = 3,
  OP_VARUINT64 = 4,
  OP_UINT32 = 5,
  OP_UINT64 = 6,
  OP_IMM = 7,
  OP_BRTABLE = 8,

  // WASM instruction
  INS_UNREACHABLE = 0x0,
  INS_NOP = 0x1,
  INS_BLOCK = 0x2,
  INS_LOOP = 0x3,
  INS_IF = 0x4,
  INS_ELSE = 0x5,
  INS_END = 0xb,
  INS_BR = 0xc,
  INS_BR_IF = 0xd,
  INS_BR_TABLE = 0xe,
  INS_RETURN = 0xf,
  INS_CALL = 0x10,
  INS_CALL_INDIRECT = 0x11,
  INS_DROP = 0x1a,
  INS_SELECT = 0x1b,
  INS_GET_LOCAL = 0x20,
  INS_SET_LOCAL = 0x21,
  INS_TEE_LOCAL = 0x22,
  INS_GET_GLOBAL = 0x23,
  INS_SET_GLOBAL = 0x24,
  INS_I32_LOAD = 0x28,
  INS_I64_LOAD = 0x29,
  INS_F32_LOAD = 0x2a,
  INS_F64_LOAD = 0x2b,
  INS_I32_LOAD8_S = 0x2c,
  INS_I32_LOAD8_U = 0x2d,
  INS_I32_LOAD16_S = 0x2e,
  INS_I32_LOAD16_U = 0x2f,
  INS_I64_LOAD8_S = 0x30,
  INS_I64_LOAD8_U = 0x31,
  INS_I64_LOAD16_S = 0x32,
  INS_I64_LOAD16_U = 0x33,
  INS_I64_LOAD32_S = 0x34,
  INS_I64_LOAD32_U = 0x35,
  INS_I32_STORE = 0x36,
  INS_I64_STORE = 0x37,
  INS_F32_STORE = 0x38,
  INS_F64_STORE = 0x39,
  INS_I32_STORE8 = 0x3a,
  INS_I32_STORE16 = 0x3b,
  INS_I64_STORE8 = 0x3c,
  INS_I64_STORE16 = 0x3d,
  INS_I64_STORE32 = 0x3e,
  INS_CURRENT_MEMORY = 0x3f,
  INS_GROW_MEMORY = 0x40,
  INS_I32_CONST = 0x41,
  INS_I64_CONST = 0x42,
  INS_F32_CONST = 0x43,
  INS_F64_CONST = 0x44,
  INS_I32_EQZ = 0x45,
  INS_I32_EQ = 0x46,
  INS_I32_NE = 0x47,
  INS_I32_LT_S = 0x48,
  INS_I32_LT_U = 0x49,
  INS_I32_GT_S = 0x4a,
  INS_I32_GT_U = 0x4b,
  INS_I32_LE_S = 0x4c,
  INS_I32_LE_U = 0x4d,
  INS_I32_GE_S = 0x4e,
  INS_I32_GE_U = 0x4f,
  INS_I64_EQZ = 0x50,
  INS_I64_EQ = 0x51,
  INS_I64_NE = 0x52,
  INS_I64_LT_S = 0x53,
  INS_I64_LT_U = 0x54,
  INS_I64_GT_U = 0x56,
  INS_I64_LE_S = 0x57,
  INS_I64_LE_U = 0x58,
  INS_I64_GE_S = 0x59,
  INS_I64_GE_U = 0x5a,
  INS_F32_EQ = 0x5b,
  INS_F32_NE = 0x5c,
  INS_F32_LT = 0x5d,
  INS_F32_GT = 0x5e,
  INS_F32_LE = 0x5f,
  INS_F32_GE = 0x60,
  INS_F64_EQ = 0x61,
  INS_F64_NE = 0x62,
  INS_F64_LT = 0x63,
  INS_F64_GT = 0x64,
  INS_F64_LE = 0x65,
  INS_F64_GE = 0x66,
  INS_I32_CLZ = 0x67,
  INS_I32_CTZ = 0x68,
  INS_I32_POPCNT = 0x69,
  INS_I32_ADD = 0x6a,
  INS_I32_SUB = 0x6b,
  INS_I32_MUL = 0x6c,
  INS_I32_DIV_S = 0x6d,
  INS_I32_DIV_U = 0x6e,
  INS_I32_REM_S = 0x6f,
  INS_I32_REM_U = 0x70,
  INS_I32_AND = 0x71,
  INS_I32_OR = 0x72,
  INS_I32_XOR = 0x73,
  INS_I32_SHL = 0x74,
  INS_I32_SHR_S = 0x75,
  INS_I32_SHR_U = 0x76,
  INS_I32_ROTL = 0x77,
  INS_I32_ROTR = 0x78,
  INS_I64_CLZ = 0x79,
  INS_I64_CTZ = 0x7a,
  INS_I64_POPCNT = 0x7b,
  INS_I64_ADD = 0x7c,
  INS_I64_SUB = 0x7d,
  INS_I64_MUL = 0x7e,
  INS_I64_DIV_S = 0x7f,
  INS_I64_DIV_U = 0x80,
  INS_I64_REM_S = 0x81,
  INS_I64_REM_U = 0x82,
  INS_I64_AND = 0x83,
  INS_I64_OR = 0x84,
  INS_I64_XOR = 0x85,
  INS_I64_SHL = 0x86,
  INS_I64_SHR_S = 0x87,
  INS_I64_SHR_U = 0x88,
  INS_I64_ROTL = 0x89,
  INS_I64_ROTR = 0x8a,
  INS_F32_ABS = 0x8b,
  INS_F32_NEG = 0x8c,
  INS_F32_CEIL = 0x8d,
  INS_F32_FLOOR = 0x8e,
  INS_F32_TRUNC = 0x8f,
  INS_F32_NEAREST = 0x90,
  INS_F32_SQRT = 0x91,
  INS_F32_ADD = 0x92,
  INS_F32_SUB = 0x93,
  INS_F32_MUL = 0x94,
  INS_F32_DIV = 0x95,
  INS_F32_MIN = 0x96,
  INS_F32_MAX = 0x97,
  INS_F32_COPYSIGN = 0x98,
  INS_F64_ABS = 0x99,
  INS_F64_NEG = 0x9a,
  INS_F64_CEIL = 0x9b,
  INS_F64_FLOOR = 0x9c,
  INS_F64_TRUNC = 0x9d,
  INS_F64_NEAREST = 0x9e,
  INS_F64_SQRT = 0x9f,
  INS_F64_ADD = 0xa0,
  INS_F64_SUB = 0xa1,
  INS_F64_MUL = 0xa2,
  INS_F64_DIV = 0xa3,
  INS_F64_MIN = 0xa4,
  INS_F64_MAX = 0xa5,
  INS_F64_COPYSIGN = 0xa6,
  INS_I32_WARP_I64 = 0xa7,
  INS_I32_TRUNC_U_F32 = 0xa9,
  INS_I32_TRUNC_S_F64 = 0xaa,
  INS_I32_TRUNC_U_F64 = 0xab,
  INS_I64_EXTEND_S_I32 = 0xac,
  INS_I64_EXTEND_U_I32 = 0xad,
  INS_I64_TRUNC_S_F32 = 0xae,
  INS_I64_TRUNC_U_F32 = 0xaf,
  INS_I64_TRUNC_S_F64 = 0xb0,
  INS_I64_TRUNC_U_F64 = 0xb1,
  INS_F32_CONVERT_S_I32 = 0xb2,
  INS_F32_CONVERT_U_I32 = 0xb3,
  INS_F32_CONVERT_S_I64 = 0xb4,
  INS_F32_CONVERT_U_I64 = 0xb5,
  INS_F32_DEMOTE_F64 = 0xb6,
  INS_F64_CONVERT_S_I32 = 0xb7,
  INS_F64_CONVERT_U_I32 = 0xb8,
  INS_F64_CONVERT_S_I64 = 0xb9,
  INS_F64_CONVERT_U_I64 = 0xba,
  INS_F64_PROMOTE_F32 = 0xbb,
  INS_I32_REINTERPRET_F32 = 0xbc,
  INS_I64_REINTERPRET_F64 = 0xbd,
  INS_F32_REINTERPRET_I32 = 0xbe,
  INS_F64_REINTERPRET_I64 = 0xbf,
  INS_INVALID = 512,
  INS_ENDING = 513,

  // Group of WASM instructions
  GRP_INVALID = 0, // cs.GRP_INVALID
  GRP_NUMBERIC = 8,
  GRP_PARAMETRIC = 9,
  GRP_VARIABLE = 10,
  GRP_MEMORY = 11,
  GRP_CONTROL = 12,
  GRP_ENDING = 13, // mark the end of the list of groups
}

export class cs_wasm {
  public op_count: number;
  public operands: cs_wasm_op[];
  constructor(arch_info_ptr: number, Memory: any) {
    this.operands = [];
    this.op_count = Memory.read(arch_info_ptr + 0, 'ubyte');
    for (let i = 0; i < this.op_count; i++) {
      const op: cs_wasm_op = {} as cs_wasm_op;
      const op_ptr: number = arch_info_ptr + 8 + i * 32;
      op.type = Memory.read(op_ptr, 'i32');
      op.size = Memory.read(op_ptr + 4, 'i32');
      switch (op.type) {
        case WASM.OP_INT7:
          op.int7 = Memory.read(op_ptr + 8, 'ubyte');
          break;
        case WASM.OP_VARUINT32:
          op.varuint32 = Memory.read(op_ptr + 8, 'u32');
          break;
        case WASM.OP_VARUINT64:
          op.varuint64 = Memory.read(op_ptr + 8, 'u64');
          break;
        case WASM.OP_UINT32:
          op.uint32 = Memory.read(op_ptr + 8, 'u32');
          break;
        case WASM.OP_UINT64:
          op.uint64 = Memory.read(op_ptr + 8, 'u64');
          break;
        case WASM.OP_IMM:
          op.immediate = [];
          for (let i = 0; i < 2; i++)
            op.immediate[i] = Memory.read(op_ptr + 8 + i, 'u32');
          break;
        case WASM.OP_BRTABLE:
          op.brtable = {
            length: Memory.read(op_ptr + 8, 'u32'),
            address: Memory.read(op_ptr + 12, 'u64'),
            default_target: Memory.read(op_ptr + 20, 'u32'),
          };
          break;
      }
      this.operands[i] = op;
    }
    return this;
  }
}
