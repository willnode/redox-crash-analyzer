
const alignUp = (number, alignment) => {
  return (number + alignment - 1) & -alignment;
};
const alignDown = (number, alignment) => {
  return number - (number % alignment);
};

export function waitForNextFrame() {
  return new Promise(resolve => {
    requestAnimationFrame(resolve);
  });
}

export const calculateExecutableLayout = (elf, ripOffset) => {
  const executableSegments = elf.program.filter(ph => ph.type === 1); // PT_LOAD
  if (executableSegments.length === 0) throw new Error("No executable PT_LOAD segments.");

  let mmapLayout = null;
  for (const segment of executableSegments) {
    let { align, vaddr, memsz, offset } = segment;
    offset = alignDown(offset, align);
    memsz = alignUp(memsz + vaddr % align, align);
    vaddr = alignDown(vaddr, align);

    if (!mmapLayout) {
      mmapLayout = { vaddr, memsz, offset };
    } else {
      if (vaddr + memsz > mmapLayout.vaddr + mmapLayout.memsz) mmapLayout.memsz = vaddr + memsz - mmapLayout.vaddr;
      if (offset + memsz > mmapLayout.offset + mmapLayout.memsz) mmapLayout.memsz = offset + memsz - mmapLayout.offset;
      if (vaddr < mmapLayout.vaddr) {
        mmapLayout.memsz -= mmapLayout.vaddr - vaddr;
        mmapLayout.vaddr = vaddr;
      }
      if (offset < mmapLayout.offset) {
        mmapLayout.memsz -= mmapLayout.offset - offset;
        mmapLayout.offset = offset;
      }
    }
  }

  const containingSegment = executableSegments.find(seg => ripOffset >= alignDown(seg.vaddr, seg.align) && ripOffset < alignDown(seg.vaddr, seg.align) + alignUp(seg.memsz + seg.vaddr % seg.align, seg.align));
  return {mmapLayout, containingSegment};
};

/**
 * @typedef {Object} MemoryModule
 * @property {string} path - The file path of the module.
 * @property {BigInt} start - The starting memory address.
 * @property {BigInt} end - The ending memory address.
 * @property {boolean} static - Whether the binary is statically linked.
 */

/**
 * @typedef {Object} MemorySymbol
 * @property {string} name - The symbol name
 * @property {number} start - The starting memory address.
 * @property {number} end - The ending memory address.
 * @property {number} size - The size of symbol in memory.
 * @property {number} offset - offset of given address
 */


/**
 * Parses the memory map from LD_DEBUG or Fault logs.
 * 
 * @param {string} ldDebugLog  The raw LD_DEBUG output.
 * @param {string} faultLog    The raw Page Fault message (for static binaries).
 * @returns {MemoryModule[]}   List of module objects {path, start, end, static}
 */
export const parseMemoryMap = (ldDebugLog, faultLog) => {
  const memoryMap = [];
  const ldLines = ldDebugLog.split('\n');

  let lastFoundPath = null;
  const foundAtRegex = /found at '(.*?)'/;
  const loadingObjectRegex = /loading object: (.*?) at (0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+) \(pie: (\w+)\)/;

  for (const line of ldLines) {
    const foundMatch = line.match(foundAtRegex);
    if (foundMatch) {
      // Remember the full path when we see "found at..."
      lastFoundPath = foundMatch[1];
      continue; // This line is processed, move to the next
    }

    const loadingMatch = line.match(loadingObjectRegex);
    if (loadingMatch) {
      let objectPath = loadingMatch[1].split("'").join("").trim();

      // If the path from "loading object:" is not absolute (i.e., it's a short name),
      // then we must use the full path we remembered from the previous line.
      if (!objectPath.startsWith('/') && lastFoundPath) {
        objectPath = lastFoundPath;
      }

      // Only add to the map if we have a valid path
      if (objectPath) {
        memoryMap.push({
          path: objectPath,
          start: BigInt(loadingMatch[2]),
          end: BigInt(loadingMatch[3]),
          static: loadingMatch[4] === "false",
        });
      }

      // Reset the remembered path so it's not accidentally reused.
      lastFoundPath = null;
    }
  }

  let staticBinary = false;
  if (memoryMap.length === 0) {
    // assume this is static binary
    const nameRegex = /NAME ([\w\/\-]+)/;
    const nameFound = faultLog.match(nameRegex);
    if (nameFound) {
      const objectPath = nameFound[1];
      memoryMap.push({
        path: objectPath,
        start: BigInt(0),
        end: 0xffffffffffffffffn, // Placeholder
        static: true,
      });
      staticBinary = true;
    }
  }

  return memoryMap;
};

/**
 * 
 * @param {BigInt} targetAddr 
 * @param {MemoryModule[]} memoryMap 
 * @returns {MemoryModule}
 */
export const getModuleForAddress = (targetAddr, memoryMap) => {
  return memoryMap.find(m => targetAddr >= m.start && (m.static || targetAddr <= m.end));
};

/**
 * 
 * @param {any} elf 
 * @param {BigInt} runtimeModuleOffset 
 * @param {BigInt} targetAddr 
 * @returns {MemorySymbol | null}
 */
export const resolveSymbolAtAddress = (elf, runtimeModuleOffset, targetAddr) => {
  for (const sym of elf.symbols) {
    if (!sym.value || !sym.size) continue;

    const symStart = Number(runtimeModuleOffset) + sym.value;
    const symEnd = symStart + sym.size;

    if (Number(targetAddr) >= symStart && Number(targetAddr) < symEnd) {
      return { 
        name: sym.name, 
        start: symStart, 
        end: symEnd, 
        size: sym.size,
        offset: Number(targetAddr) - symStart 
      };
    }
  }
  return null;
};

/**
 * Guess the correct file from Chromium File handler
 * @param {*} dirHandle 
 * @param {string} path 
 * @returns 
 */
export const findFileInDirectory = async (dirHandle, path) => {
  if (path.startsWith('lib')) {
    path = 'usr/' + path;
  }
  if (path == 'usr/lib/libc.so.6' || path.includes('ld.so')) {
    path = 'usr/lib/libc.so';
  }
  if (path == 'usr/bin/env') {
    path = 'usr/bin/coreutils';
  }
  if (path == 'usr/bin/sh') {
    path = 'usr/bin/bash';
  }
  const parts = path.split('/').filter(p => p && p !== '.');
  let currentHandle = dirHandle;
  for (const part of parts.slice(0, -1)) {
    currentHandle = await currentHandle.getDirectoryHandle(part, { create: false });
  }
  const fileName = parts[parts.length - 1];
  try {
    return (await currentHandle.getFileHandle(fileName, { create: false }));
  } catch (error) {
    // this is probably pointing to a symlink, but symlink is not supported here
    let files = await Array.fromAsync(currentHandle.entries());
    let file = files.find(x => x[0].startsWith(fileName));
    if (file) {
      return file[1];
    }
    throw new Error(`Can't find file ${path}.\n Chrome API does not support symlink. You might want to\n alter the path in LD_DEBUG or page fault input to fix this issue.`);
  }
};

export const analyzeCrashCause = (log) => {
  let summary = "Unknown Exception";
  let detail = "";

  // AArch64 error from parsing ESR
  const esrMatch = log.match(/ESR_EL1:\s+([0-9a-fA-Fx]+)/);
  const farMatch = log.match(/FAR_EL1:\s+([0-9a-fA-Fx]+)/);

  if (esrMatch) {
    const esr = parseInt(esrMatch[1], 16);
    const ec = (esr >> 26) & 0x3F; // Exception Class
    const iss = esr & 0x1FFFFFF;  // Instruction Specific Syndrome

    const aarch64EC = {
      0x00: "Unknown Reason",
      0x01: "Trapped WFI or WFE instruction",
      0x0E: "Illegal Execution State",
      0x20: "Instruction Abort (Lower EL)",
      0x21: "Instruction Abort (Same EL)",
      0x22: "PC Alignment Fault",
      0x24: "Data Abort (Lower EL)",
      0x25: "Data Abort (Same EL)",
      0x26: "Stack Alignment Fault",
      0x3C: "Breakpoint (BKPT/Software Step)"
    };

    summary = `AArch64 Exception: ${aarch64EC[ec] || `EC 0x${ec.toString(16)}`}`;

    // Decode Data Abort Details
    if (ec === 0x24 || ec === 0x25) {
      const isWrite = (iss >> 6) & 1;
      detail = `Type: ${isWrite ? 'Write' : 'Read'} Access Violation`;
    }

    if (farMatch) {
      const far = farMatch[1];
      detail += ` | Faulting Address (FAR): ${far}`;
      if (parseInt(far, 16) === 0) detail += " (Null Pointer Dereference)";
    }

    return { summary, detail };
  }

  // x86_64 error strings, coming from kernel code
  const x86Exceptions = [
    { msg: "Divide by zero", kind: 0 },
    { msg: "Debug trap", kind: 1 },
    { msg: "Breakpoint trap", kind: 3 },
    { msg: "Overflow trap", kind: 4 },
    { msg: "Bound range exceeded fault", kind: 5 },
    { msg: "Invalid opcode fault", kind: 6 },
    { msg: "Device not available fault", kind: 7 },
    { msg: "Double fault", kind: 8 },
    { msg: "Invalid TSS fault", kind: 10 },
    { msg: "Segment not present fault", kind: 11 },
    { msg: "Stack segment fault", kind: 12 },
    { msg: "Protection fault", kind: 13 },
    { msg: "Page fault", kind: 14 },
    { msg: "FPU floating point fault", kind: 16 },
    { msg: "Alignment check fault", kind: 17 },
    { msg: "Machine check fault", kind: 18 },
    { msg: "SIMD floating point fault", kind: 19 }
  ];

  for (const ex of x86Exceptions) {
    if (log.toLowerCase().includes(ex.msg.toLowerCase())) {
      summary = `x86_64 ${ex.msg} (#${ex.kind})`;

      if (ex.kind === 14) { // Page Fault
        const pfDetail = log.match(/Page fault:\s+([0-9a-fA-F]+)\s+PageFaultError\s*\{([\s\S]*?)\}/);
        if (pfDetail) detail = `Addr: 0x${pfDetail[1]} | Flags: ${pfDetail[2].replace(/\s+/g, ' ')}`;
      }

      if (ex.kind === 13) { // Protection Fault
        const protMatch = log.match(/Protection fault code=([0-9a-fA-Fx]+)/);
        if (protMatch) detail = `Error Code: ${protMatch[1]}`;
      }

      return { summary, detail };
    }
  }

  if (log.includes("GUARD PAGE")) {
    return { summary: "Stack Overflow", detail: "Process hit a kernel-protected Guard Page." };
  }

  return { summary, detail: "No specific exception pattern recognized in logs." };
};

/**
 * Disassembles a window of instructions around a target address.
 * 
 * @param {Object} elf - Parsed ELF object
 * @param {ArrayBuffer} arrayBuffer - Raw file buffer
 * @param {BigInt} runtimeModuleOffset - Base offset of the module
 * @param {BigInt|Number} targetAddr - The address to center around
 * @param {Number} startDisasmAddr - The safe start boundary (usually sym.start)
 * @param {Number} linesBefore - How many instructions before target to return
 * @param {Number} linesAfter - How many instructions after target to return
 * @returns {Array} Array of Capstone instruction objects
 */
export const getInstructionWindow = (elf, arrayBuffer, runtimeModuleOffset, targetAddr, startDisasmAddr, linesBefore, linesAfter) => {
  let arch, mode;
  if (elf.header.machine === 62) { arch = window.cs.ARCH_X86; mode = window.cs.MODE_64; }
  else if (elf.header.machine === 183) { arch = window.cs.ARCH_ARM64; mode = window.cs.MODE_ARM; }
  else return []; // Unsupported arch

  const textSection = elf.sections.find(s => s.name === '.text');
  if (!textSection) return [];

  const csInst = new window.cs.Capstone(arch, mode);
  const runtimeTextSectionStart = runtimeModuleOffset + BigInt(textSection.addr);
  const code = new Uint8Array(arrayBuffer, textSection.offset, textSection.size);

  const startAddrNum = Number(startDisasmAddr);
  const targetAddrNum = Number(targetAddr);
  const offsetInTextSection = startAddrNum - Number(runtimeTextSectionStart);

  if (offsetInTextSection < 0 || offsetInTextSection >= code.length) {
    csInst.close();
    return [];
  }

  // Calculate safe chunk size: Distance to target + enough room for trailing instructions
  const bytesToTarget = Math.max(0, targetAddrNum - startAddrNum);
  const chunkSize = bytesToTarget + (linesAfter * 15) + 100; // 15 bytes max per x86 instruction
  const chunk = code.slice(offsetInTextSection, offsetInTextSection + chunkSize);

  // Disassemble
  const instructions = csInst.disasm(chunk, startAddrNum, bytesToTarget + linesAfter + 50);
  csInst.close(); // Prevent memory leaks!

  const targetIdx = instructions.findIndex(i => i.address >= targetAddrNum);
  if (targetIdx !== -1) {
    const startIdx = Math.max(0, targetIdx - linesBefore);
    const endIdx = Math.min(instructions.length, targetIdx + linesAfter + 1);
    return instructions.slice(startIdx, endIdx);
  }
  return [];
};
