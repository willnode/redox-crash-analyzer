
const { createApp, ref, computed, nextTick } = Vue;

// --- Configuration for the disassembly window ---
const LINES_BEFORE = 200;
const LINES_AFTER = 200;

// How many extra bytes to read before the target address to ensure we can disassemble `LINES_BEFORE` instructions.
// Variable-length instructions mean we have to guess. 10 bytes per instruction is a safe overestimate.
const CONTEXT_BYTES = LINES_BEFORE * 10;

const alignUp = (number, alignment) => {
  return (number + alignment - 1) & -alignment;
};
const alignDown = (number, alignment) => {
  return number - (number % alignment);
};

function waitForNextFrame() {
  return new Promise(resolve => {
    requestAnimationFrame(resolve);
  });
}

const findFileInDirectory = async (dirHandle, path) => {
  if (path.startsWith('lib')) {
    path = 'usr/' + path;
  }
  if (path == 'usr/lib/libc.so.6') {
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
 * Parses the memory map from LD_DEBUG or Fault logs.
 * @param {string} ldDebugLog - The raw LD_DEBUG output.
 * @param {string} faultLog - The raw Page Fault message (for static binaries).
 * @returns {Array} List of module objects {path, start, end, static}
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
      lastFoundPath = foundMatch[1];
      continue;
    }

    const loadingMatch = line.match(loadingObjectRegex);
    if (loadingMatch) {
      let objectPath = loadingMatch[1].split("'").join("").trim();
      if (!objectPath.startsWith('/') && lastFoundPath) {
        objectPath = lastFoundPath;
      }

      if (objectPath) {
        memoryMap.push({
          path: objectPath,
          start: BigInt(loadingMatch[2]),
          end: BigInt(loadingMatch[3]),
          static: loadingMatch[4] === "false",
        });
      }
      lastFoundPath = null;
    }
  }

  // Fallback for static binaries (Redox specific)
  if (memoryMap.length === 0) {
    const nameRegex = /NAME ([\w\/\-]+)/;
    const nameFound = faultLog.match(nameRegex);
    if (nameFound) {
      memoryMap.push({
        path: nameFound[1],
        start: 0n,
        end: 0xffffffffffffffffn, // Placeholder
        static: true,
      });
    }
  }

  return memoryMap;
};

/**
 * Resolves a runtime address to a symbol and file path.
 * @param {BigInt} targetAddr - The runtime address (RIP/PC).
 * @param {Array} memoryMap - Result from parseMemoryMap.
 * @param {FileSystemDirectoryHandle} sysroot - The user selected directory handle.
 * @param {Object} deps - Object containing findFileInDirectory and ELFParser.
 */
export const getAddressMetadata = async (targetAddr, memoryMap, sysroot) => {
  const module = memoryMap.find(m => targetAddr >= m.start && (m.static || targetAddr <= m.end));

  if (!module) {
    return {
      addr: '0x' + targetAddr.toString(16).padStart(8, '0'),
      symbol: '<External/Unknown>',
      module: '??',
      gdb: ''
    };
  }

  const runtimeModuleOffset = module.start * BigInt(module.static ? 0 : 1);
  const pathModule = module.path.replace(/^\//, '');

  try {
    const fileHandle = await findFileInDirectory(sysroot, pathModule);
    const file = await fileHandle.getFile();
    const arrayBuffer = await file.arrayBuffer();
    const elf = new elfist.ELFParser(new Uint8Array(arrayBuffer));

    let foundSym = "???";
    let gdbCmd = `gdb -batch -ex 'file ${pathModule}'`;

    // Search symbols
    for (const sym of elf.symbols) {
      if (!sym.value || !sym.size) continue;

      const symStart = Number(runtimeModuleOffset) + sym.value;
      const symEnd = symStart + sym.size;

      if (Number(targetAddr) >= symStart && Number(targetAddr) < symEnd) {
        const offset = Number(targetAddr) - symStart;
        foundSym = `${sym.name} + 0x${offset.toString(16)}`;
        gdbCmd += ` -ex 'disassemble 0x${symStart.toString(16)}, 0x${symEnd.toString(16)}'`;
        return {
          addr: '0x' + targetAddr.toString(16),
          symbol: foundSym,
          module: pathModule,
          gdb: gdbCmd
        };
      }
    }

    return {
      addr: '0x' + targetAddr.toString(16),
      symbol: elf.symbols.length == 0 ? '(stripped)' : '(unknown)',
      module: pathModule,
      gdb: gdbCmd + ` -ex 'info line *0x${targetAddr.toString(16)}'`
    };
  } catch (e) {
    return {
      addr: '0x' + targetAddr.toString(16),
      symbol: '',
      module: pathModule,
      gdb: `file ${pathModule}`
    };
  }
};


const setup = function () {
  const faultLog = ref(window.sessionStorage.faultLog || '');
  const ldDebugLog = ref(window.sessionStorage.ldDebugLog || '');
  const sysrootDirHandle = ref(null);
  const disassemblyOutput = ref('Enter the Page fault message and click "Analyze Crash"');
  const isLoading = ref(false);
  const error = ref(null);
  const successMessage = ref(null);

  const isReady = computed(() => faultLog.value && sysrootDirHandle.value);

  const analysisData = ref(null);
  const jumpAddress = ref('');
  const currentSymbolName = ref('');
  const currentSymbolName2 = ref('');
  const callStacks = ref([]);

  const updateSymbolInfo = (ripNum) => {
    if (!analysisData.value?.symbols) {
      currentSymbolName.value = '';
      currentSymbolName2.value = '';
      return;
    }
    const { symbols, runtimeModuleOffset, pathModule } = analysisData.value;

    for (const sym of symbols) {
      if (!sym.value || !sym.size) continue; // skip broken

      const symStart = Number(runtimeModuleOffset) + sym.value;
      const symEnd = symStart + sym.size;

      if (ripNum >= symStart && ripNum < symEnd) {
        const offset = ripNum - symStart;
        currentSymbolName.value = `Symbol: ${sym.name} (0x${symStart.toString(16)}:0x${symEnd.toString(16)}) +0x${offset.toString(16)}`;
        currentSymbolName2.value = `gdb -batch -ex 'file ${pathModule}' -ex 'disassemble 0x${symStart.toString(16)}, 0x${symEnd.toString(16)}'`;
        return { start: symStart, end: symEnd, size: sym.size };
      }
    }
    currentSymbolName.value = 'Symbol: <not found in table>';
    currentSymbolName.value2 = '';
  };

  const selectDirectory = async () => {
    try {
      sysrootDirHandle.value = await window.showDirectoryPicker();
      error.value = null;
    } catch (err) {
      console.error("Error selecting directory:", err);
      error.value = "Failed to select directory. This feature only works on Chromium-based browsers.";
    }
  };

  /** @param {BigInteger} targetAddrBigInt  */
  const renderDisassemblyWindow = async (targetAddrBigInt) => {
    // Parse memory map from LD_DEBUG
    const rip = targetAddrBigInt;
    const ripNum = Number(targetAddrBigInt);
    const memoryMap = [];
    const ldLines = ldDebugLog.value.split('\n');

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
      const nameFound = faultLog.value.match(nameRegex);
      if (nameFound) {
        const objectPath = nameFound[1];
        memoryMap.push({
          path: objectPath,
          start: BigInt(0),
          end: rip, // don't bother getting a correct value
          static: true,
        });
        staticBinary = true;
      }
    }

    if (memoryMap.length === 0) throw new Error("Could not parse any loaded objects from LD_DEBUG output.");
    disassemblyOutput.value += `\nParsed ${memoryMap.length} loaded objects.`;

    // Find the faulting module
    const faultingModule = memoryMap.find(m => rip >= m.start && rip <= m.end);
    if (!faultingModule) throw new Error(`Could not find a module containing the RIP address 0x${rip.toString(16)}.\n The code maybe generated in the application.`);
    disassemblyOutput.value += `\nRIP is inside module: ${faultingModule.path}`;

    // Calculate offset
    const runtimeModuleOffset = faultingModule.start * BigInt(faultingModule.static ? 0 : 1); // non PIE object don't remap start offset, according to relibc
    const ripOffset = rip - runtimeModuleOffset;
    disassemblyOutput.value += `\nCalculated offset: 0x${ripOffset.toString(16)}`;
    if (faultingModule.static) {
      disassemblyOutput.value += " (unchanged because it's not PIE)";
    }

    // Find the file in the selected sysroot directory
    let pathModule = (faultingModule.path + '').replace(/^\//, ''); // Remove leading '/'

    disassemblyOutput.value += `\nSearching for ${pathModule} in sysroot...`;
    const fileHandle = await findFileInDirectory(sysrootDirHandle.value, pathModule);
    const file = await fileHandle.getFile();
    disassemblyOutput.value += `\nFound file: ${file.name}`;

    // Read and disassemble the file using elfist
    const arrayBuffer = await file.arrayBuffer();
    const elf = new window.elfist.ELFParser(new Uint8Array(arrayBuffer));

    // get ALL PT_LOAD segments
    const executableSegments = elf.program.filter(ph => ph.type === 1);

    if (executableSegments.length === 0) {
      throw new Error("Could not find any executable PT_LOAD segments in the ELF file.");
    }

    let mmapLayout = null, containingSegment = null;
    for (const segment of executableSegments) {
      let { align, vaddr, memsz, offset } = segment;
      // offset is usually zero on Redox GCC
      offset = alignDown(offset, align);
      memsz = alignUp(memsz + vaddr % align, align);
      vaddr = alignDown(vaddr, align);

      disassemblyOutput.value += `\nLoaded code ${vaddr.toString(16)}-${(vaddr + memsz).toString(16)}`;
      if (ripOffset >= vaddr && ripOffset < vaddr + memsz) {
        containingSegment = segment;
        disassemblyOutput.value += ` and selected`;
      }
      if (mmapLayout == null) {
        mmapLayout = { vaddr, memsz, offset };
      } else {
        if (vaddr + memsz > mmapLayout.vaddr + mmapLayout.memsz) {
          mmapLayout.memsz = vaddr + memsz - mmapLayout.vaddr;
        }
        if (offset + memsz > mmapLayout.offset + mmapLayout.memsz) {
          mmapLayout.memsz = offset + memsz - mmapLayout.offset;
        }
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

    if (!containingSegment) {
      throw new Error(`RIP 0x${rip.toString(16)} does not fall within any executable PT_LOAD segment.`);
    }
    const PF_X = 1;
    if (!(containingSegment.flags & PF_X)) {
      // For now, we'll throw an error, as we are set up to disassemble code.
      // This could be expanded later to show a hex dump of the data instead.
      throw new Error(`RIP 0x${rip.toString(16)} is in a non-executable segment (flags: ${containingSegment.flags}).\n This indicates a data access fault, not an instruction fetch fault.`);
    }
    const moduleSize = Number(faultingModule.end - faultingModule.start);
    if (!staticBinary && mmapLayout.memsz != moduleSize) {
      throw new Error(`Mmap size ${mmapLayout.memsz.toString(16)} is different than module size ${moduleSize.toString(16)}. \n Relibc load strategy may have changed.`);
    }

    let arch, mode;
    if (elf.header.machine === 62) { // EM_X86_64
      arch = cs.ARCH_X86; mode = cs.MODE_64;
    } else if (elf.header.machine === 183) { // EM_AARCH64
      arch = cs.ARCH_ARM64; mode = cs.MODE_ARM;
    } else {
      throw new Error(`Unsupported machine architecture: ${elf.header.machine}`);
    }
    const textSection = elf.sections.find(s => s.name === '.text');
    if (!textSection) {
      throw new Error("Could not find the .text section in the ELF file.");
    }
    const code = new Uint8Array(arrayBuffer, textSection.offset, textSection.size);

    // Useful for diagnostics
    console.log(window.elf = elf);

    analysisData.value = {
      runtimeSegmentStart: runtimeModuleOffset + BigInt(mmapLayout.vaddr),
      runtimeTextSectionStart: runtimeModuleOffset + BigInt(textSection.addr),
      runtimeModuleOffset,
      symbols: elf.symbols,
      file: file,
      pathModule,
      csInst: new cs.Capstone(arch, mode),
    };

    jumpAddress.value = "0x" + rip.toString(16);

    if (!analysisData.value) return;
    const { csInst, runtimeSegmentStart, runtimeTextSectionStart } = analysisData.value;
    const symbol = updateSymbolInfo(ripNum);

    successMessage.value = `Rendering view around 0x${ripNum.toString(16)}...`;

    const targetOffsetInCode = Number(targetAddrBigInt - runtimeTextSectionStart);

    if (targetOffsetInCode < 0 || targetOffsetInCode >= code.length) {
      throw new Error(`Address 0x${ripNum.toString(16)} is outside the .text section (runtime start: 0x${runtimeSegmentStart.toString(16)}, size: 0x${code.length.toString(16)}).`);
    }

    const startOffsetInData = Math.max(0, targetOffsetInCode - CONTEXT_BYTES);
    let instructions = [];
    let currentAddr = symbol?.start || (ripNum - 500);
    const endAddr = symbol?.end || (ripNum + 500);
    let offsetInTextSection = currentAddr - Number(runtimeTextSectionStart);
    while (true) {
      const safeOffset = Math.max(0, offsetInTextSection);
      const codeChunked = code.slice(safeOffset);

      let i = csInst.disasm(codeChunked, currentAddr, 1000);

      if (!i || i.length === 0) break;

      for (const insn of i) {
        if (insn.address < endAddr) {
          instructions.push(insn);
          currentAddr = insn.address + insn.size;
        } else {
          currentAddr = endAddr;
          break;
        }
      }

      const lastInsn = i[i.length - 1];
      currentAddr = lastInsn.address + lastInsn.size;

      offsetInTextSection = currentAddr - Number(runtimeTextSectionStart);
      if (currentAddr >= ripNum || instructions.length > 5000) {
        break;
      }

      const line = `\n  Seeking 0x${currentAddr.toString(16)} ${Math.trunc((currentAddr - Number(runtimeTextSectionStart)) / (ripNum - Number(runtimeTextSectionStart)) * 1000) / 10}%`;
      console.log(line);
      disassemblyOutput.value += line;
      await waitForNextFrame();
    }

    const minAddr = instructions[0].address;
    const maxAddr = instructions[instructions.length - 1].address;
    disassemblyOutput.value += `\n Instruction start at 0x${minAddr.toString(16)}`;
    disassemblyOutput.value += `\n Instruction end at 0x${maxAddr.toString(16)}`;
    disassemblyOutput.value += `\n looking at 0x${ripNum.toString(16)}`;

    const isStackReturnAddr = callStacks.value.slice(1).some(addr =>
      BigInt(addr) === targetAddrBigInt
    );
    let targetIndex = instructions.findIndex(insn => insn.address >= ripNum);
    if (targetIndex === -1) {
      throw new Error(`Could not locate instruction at or after 0x${ripNum.toString(16)}.`);
    }

    // Could be a return address, which should highlight previous instruction
    if (isStackReturnAddr && targetIndex > 0) {
      targetIndex = targetIndex - 1;
      var effectiveHighlightAddr = instructions[targetIndex].address;
    } else {
      var effectiveHighlightAddr = ripNum;
    }

    if (targetIndex === -1) {
      throw new Error(`Could not locate instruction at or after 0x${ripNum.toString(16)}.`);
    }

    const startIndex = Math.max(0, targetIndex - LINES_BEFORE);
    const endIndex = targetIndex + LINES_AFTER + 1;
    const displayInstructions = instructions.slice(startIndex, endIndex);

    // Format for display
    let htmlOutput = '';
    for (const insn of displayInstructions) {
      const isTargetLine = insn.address === effectiveHighlightAddr;
      const offsetStr = `0x${insn.address.toString(16).padStart(8, '0')}`;
      const bytesStr = insn.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
      htmlOutput += `<span ${isTargetLine ? 'class="highlight" id="target-line"' : ''}>`;
      htmlOutput += `<span class="offset">${offsetStr}:</span> <span class="bytes">${bytesStr.padEnd(20)}</span> <span class="mnemonic">${insn.mnemonic}</span> ${insn.op_str}\n`;
      htmlOutput += `</span>`;
    }

    disassemblyOutput.value = htmlOutput;
    successMessage.value = `Showing ${displayInstructions.length} instructions around 0x${ripNum.toString(16)} (${file.name})`;
    if (elf.symbols.length == 0) {
      successMessage.value += " <Symbol stripped!>";
    }
    // Scroll the target line into view
    await nextTick();
    const targetLine = document.getElementById('target-line');
    if (targetLine) {
      targetLine.scrollIntoView({ behavior: 'auto', block: 'center' });
    }
  };

  const jumpToAddress = async () => {
    if (!jumpAddress.value) return;
    try {
      isLoading.value = true;
      error.value = null;
      const targetAddr = BigInt("0x" + jumpAddress.value.replace('0x', ''));
      disassemblyOutput.value = '';
      currentSymbolName.value = '';
      currentSymbolName2.value = '';
      await renderDisassemblyWindow(targetAddr);
    } catch (e) {
      error.value = e.message;
    } finally {
      isLoading.value = false;
    }
  };

  const jumpToStack = async (value) => {
    jumpAddress.value = value;
    await jumpToAddress();
  };

  const analyzeCrash = async () => {
    isLoading.value = true;
    error.value = null;
    successMessage.value = null;
    disassemblyOutput.value = 'Starting analysis...';
    callStacks.value = [];

    window.sessionStorage.faultLog = faultLog.value;
    window.sessionStorage.ldDebugLog = ldDebugLog.value;
    analysisData.value = null;

    try {
      // Parse RIP from fault log
      const ripMatch = faultLog.value.match(/(RIP|ELR_EL1):\s+([0-9a-fA-Fx]+)/);
      if (!ripMatch) throw new Error("Could not find RIP address in the page fault message.");
      const rip = BigInt('0x' + ripMatch[2]);
      disassemblyOutput.value += `\nFound RIP: 0x${rip.toString(16)}`;
      // Find more call stack
      callStacks.value.push('0x' + ripMatch[2].toLowerCase().replace(/^[0\.]+/, ""));
      for (const stackMatch of faultLog.value.matchAll(/PC\s+([0-9a-fA-Fx]+)/g)) {
        callStacks.value.push('0x' + stackMatch[1].replace(/^[0\.]+/, ""));
      }

      // Perform the initial render around the RIP
      await renderDisassemblyWindow(rip);

    } catch (e) {
      console.error("Analysis failed:", e);
      error.value = e.message || e.toString();
      disassemblyOutput.value += `\nAnalysis failed.\n\n${error.value}`;
      analysisData.value = null; // Clear context on failure
    } finally {
      isLoading.value = false;
    }
  };

  const generateFullReport = async () => {
    isLoading.value = true;
    disassemblyOutput.value = 'Parsing memories...\n';
    try {
      const memoryMap = parseMemoryMap(ldDebugLog.value, faultLog.value);

      const { summary, detail } = analyzeCrashCause(faultLog.value);
      let reportText = `CRASH ANALYSIS\n`;
      reportText += `--------------\n`;
      reportText += ` Summary: ${summary}\n`;
      reportText += ` Detail:  ${detail}\n`;
      let stackText = '\nStack Detail\n';
      let gdbText = '\nGDB commands\n';
      let i = 0;
      for (const addrStr of callStacks.value) {
        disassemblyOutput.value += `[${i++} / ${callStacks.value.length}] Reading ${addrStr}\n`;

        const meta = await getAddressMetadata(
          BigInt(addrStr),
          memoryMap,
          sysrootDirHandle.value,
        );

        stackText += `#${i.toString().padStart(2)} ${meta.addr} | [${meta.module}] ${meta.symbol}\n`;
        gdbText += `#${i.toString().padStart(2)} ${meta.gdb || '??'}\n`;
      }

      disassemblyOutput.value = reportText + stackText + gdbText;
      isLoading.value = false;
      error.value = '';
      currentSymbolName.value = '';
      currentSymbolName2.value = '';
    } catch (e) {
      console.error("Analysis failed:", e);
      error.value = e.message || e.toString();
      disassemblyOutput.value += `\nAnalysis failed.\n\n${error.value}`;
      analysisData.value = null; // Clear context on failure
    }
  };

  // Cleanup Capstone instance when component is unmounted
  // onUnmounted(() => { if (analysisData.value) analysisData.value.cs.close(); });

  return {
    faultLog, ldDebugLog, sysrootDirHandle, disassemblyOutput, isLoading, error,
    successMessage, isReady, analysisData, jumpAddress, currentSymbolName, currentSymbolName2, callStacks,
    selectDirectory, analyzeCrash, jumpToAddress, jumpToStack, generateFullReport
  };
};

createApp({ setup }).mount('#app');
