
const { createApp, ref, computed, nextTick } = Vue;
import {
  waitForNextFrame, analyzeCrashCause, calculateExecutableLayout,
  findFileInDirectory, getModuleForAddress, parseMemoryMap, resolveSymbolAtAddress,
  getInstructionWindow,
} from './utils.js';

// --- Configuration for the disassembly window ---
const LINES_BEFORE = 200;
const LINES_AFTER = 200;


/**
 * Resolves a runtime address to a symbol and file path.
 * 
 * @param {BigInt} targetAddr  The runtime address (RIP/PC).
 * @param {MemoryModule[]} memoryMap    Result from parseMemoryMap.
 * @param {FileSystemDirectoryHandle} sysroot  The user selected directory handle.
 * @param {Object} deps        Object containing findFileInDirectory and ELFParser.
 */
export const getAddressMetadata = async (targetAddr, memoryMap, sysroot, isStackReturnAddr = false) => {
  const module = getModuleForAddress(targetAddr, memoryMap);

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

    let gdbCmd = `gdb -batch -ex 'file ${pathModule}'`;
    let asmPreview = '';


    const sym = resolveSymbolAtAddress(elf, runtimeModuleOffset, targetAddr);
    const startDisasmAddr = sym ? sym.start : Number(targetAddr) - 30;
    const instructions = getInstructionWindow(elf, arrayBuffer, runtimeModuleOffset, targetAddr, startDisasmAddr, 3, 3);
    const targetIdx = instructions.findIndex(i => i.address >= Number(targetAddr));

    if (instructions.length > 0 && targetIdx !== -1) {
      let effectiveTargetIdx = targetIdx;
      // Shift backward by 1 to highlight the CALL instruction instead of the return address
      if (isStackReturnAddr && effectiveTargetIdx > 0) {
        effectiveTargetIdx -= 1;
      }
      const effectiveHighlightAddr = instructions[effectiveTargetIdx].address;
      // Center the 7 lines around the effective target instead of the original target
      const startIdx = Math.max(0, effectiveTargetIdx - 3);
      const endIdx = Math.min(instructions.length, effectiveTargetIdx + 4);
      asmPreview = instructions.slice(startIdx, endIdx).map(insn => {
        const isTarget = insn.address === effectiveHighlightAddr;
        const prefix = isTarget ? "=>" : "  ";
        const addrStr = insn.address.toString(16).padStart(8, '0');
        return `${prefix} 0x${addrStr}:  ${insn.mnemonic.padEnd(6)} ${insn.op_str}`;
      }).join('\n');
    } else {
      asmPreview = '  [No assembly data]';
    }

    if (sym) {
      return {
        addr: `0x${targetAddr.toString(16)}`,
        symbol: `${sym.name} + 0x${sym.offset.toString(16)}`,
        module: pathModule,
        gdb: gdbCmd + ` -ex 'disassemble 0x${sym.start.toString(16)}, 0x${sym.end.toString(16)}'`,
        asmPreview
      };
    }

    return {
      addr: '0x' + targetAddr.toString(16),
      symbol: elf.symbols.length == 0 ? '(stripped)' : '(unknown)',
      module: pathModule,
      gdb: gdbCmd + ` -ex 'info line *0x${targetAddr.toString(16)}'`,
      asmPreview
    };
  } catch (e) {
    console.error(e);
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
    if (!analysisData.value?.elf) {
      currentSymbolName.value = '';
      currentSymbolName2.value = '';
      return null;
    }

    const { elf, runtimeModuleOffset, pathModule } = analysisData.value;

    const sym = resolveSymbolAtAddress(elf, runtimeModuleOffset, ripNum);

    if (sym) {
      currentSymbolName.value = `Symbol: ${sym.name} (0x${sym.start.toString(16)}:0x${sym.end.toString(16)}) +0x${sym.offset.toString(16)}`;
      currentSymbolName2.value = `gdb -batch -ex 'file ${pathModule}' -ex 'disassemble 0x${sym.start.toString(16)}, 0x${sym.end.toString(16)}'`;

      // Return the bounds so Capstone knows where to start/stop disassembling
      return { start: sym.start, end: sym.end, size: sym.end - sym.start };
    }

    currentSymbolName.value = 'Symbol: <not found in table>';
    currentSymbolName2.value = '';
    return null;
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

    const memoryMap = parseMemoryMap(ldDebugLog.value, faultLog.value);

    let staticBinary = false;
    if (memoryMap.length === 1 && memoryMap[0].static && memoryMap[0].start === 0n) {
      staticBinary = true;
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
    let { mmapLayout, containingSegment } = calculateExecutableLayout(elf, ripOffset);

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
    console.log(`${file.name}: `, window.elf = elf);

    analysisData.value = {
      runtimeSegmentStart: runtimeModuleOffset + BigInt(mmapLayout.vaddr),
      runtimeTextSectionStart: runtimeModuleOffset + BigInt(textSection.addr),
      runtimeModuleOffset,
      elf,
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

    const startDisasmAddr = symbol ? symbol.start : (ripNum - 500);

    // Grab exactly the 401 instructions we need (200 before + 1 target + 200 after)
    const displayInstructions = getInstructionWindow(
      elf, arrayBuffer, runtimeModuleOffset, targetAddrBigInt, startDisasmAddr, LINES_BEFORE, LINES_AFTER
    );

    if (displayInstructions.length === 0) {
      throw new Error(`Could not disassemble instructions around 0x${ripNum.toString(16)}`);
    }

    let effectiveHighlightAddr = ripNum;
    const isStackReturnAddr = callStacks.value.slice(1).some(addr => BigInt(addr) === targetAddrBigInt);

    // If it's a return address, highlight the instruction immediately BEFORE the return (the CALL)
    if (isStackReturnAddr) {
      const targetIndex = displayInstructions.findIndex(insn => insn.address >= ripNum);
      if (targetIndex > 0) effectiveHighlightAddr = displayInstructions[targetIndex - 1].address;
    }

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
        disassemblyOutput.value += `[${i} / ${callStacks.value.length}] Reading ${addrStr}\n`;

        const isStackReturnAddr = i++ > 0;
        const meta = await getAddressMetadata(
          BigInt(addrStr),
          memoryMap,
          sysrootDirHandle.value,
          isStackReturnAddr,
        );

        stackText += `#${i.toString().padStart(2)} ${meta.addr} | [${meta.module}] ${meta.symbol}\n`;
        stackText += `${meta.asmPreview || '  [No assembly location]'}\n`;
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
