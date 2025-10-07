<script setup lang="ts">
import { ref, computed, nextTick, type Ref } from 'vue';
import * as elfist from "@wokwi/elfist";
// TODO: Typescript?
import cs from "./capstone.js";

// --- Configuration for the disassembly window ---
const LINES_BEFORE = 100;
const LINES_AFTER = 100;

// How many extra bytes to read before the target address to ensure we can disassemble `LINES_BEFORE` instructions.
// Variable-length instructions mean we have to guess. 10 bytes per instruction is a safe overestimate.
const CONTEXT_BYTES = LINES_BEFORE * 10;

const alignUp = (number: number, alignment: number) => {
  return (number + alignment - 1) & -alignment;
};
const alignDown = (number: number, alignment: number) => {
  return number - (number % alignment);
};

const bigIntMax = (args: BigInt[]) => args.reduce((m, e) => e > m ? e : m, BigInt(Number.MIN_SAFE_INTEGER));
const bigIntMin = (args: BigInt[]) => args.reduce((m, e) => e < m ? e : m, BigInt(Number.MAX_SAFE_INTEGER));

const faultLog = ref(window.sessionStorage.faultLog || '');
const ldDebugLog = ref(window.sessionStorage.ldDebugLog || '');
const sysrootDirHandle: Ref<string | null> = ref(null);
const disassemblyOutput: Ref<string> = ref('Enter the Page fault message and click "Start Analyze"');
const isLoading: Ref<boolean> = ref(false);
const error: Ref<string | null> = ref(null);
const successMessage: Ref<string | null> = ref(null);

const isReady = computed(() => faultLog.value && ldDebugLog.value && sysrootDirHandle.value);

const analysisData: Ref<{
  code: Uint8Array, symbols: elfist.ELFSymbol[], runtimeModuleOffset: BigInt,
  runtimeSegmentStart: BigInt, runtimeTextSectionStart: BigInt, cs: any
} | null> = ref(null);
const instructionData: Ref<any> = ref(null);
const jumpAddress = ref('');
const currentSymbolName = ref('');


const updateSymbolInfo = (targetAddrNum: number) => {
  if (!analysisData.value?.symbols) {
    currentSymbolName.value = '';
    return;
  }
  const { symbols, runtimeModuleOffset } = analysisData.value;

  for (const sym of symbols) {
    if (!sym.value || !sym.size) continue; // skip broken

    const symStart = Number(runtimeModuleOffset) + sym.value;
    const symEnd = symStart + sym.size;

    if (targetAddrNum >= symStart && targetAddrNum < symEnd) {
      const offset = targetAddrNum - symStart;
      currentSymbolName.value = `Symbol: ${sym.name} +0x${offset.toString(16)}`;
      return;
    }
  }
  currentSymbolName.value = 'Symbol: <not found in table>';
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

const findFileInDirectory = async (dirHandle: any, path: string) => {
  if (path.startsWith('lib')) {
    path = 'usr/' + path;
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

const renderDisassemblyWindow = async (targetAddrBigInt) => {
  if (!analysisData.value) return;
  const { code, cs, runtimeSegmentStart, runtimeTextSectionStart } = analysisData.value;
  const targetAddrNum = Number(targetAddrBigInt);

  successMessage.value = `Rendering view around 0x${targetAddrNum.toString(16)}...`;

  const targetOffsetInCode = Number(targetAddrBigInt - runtimeTextSectionStart);

  if (instructionData.value) {
    instructionData.value.dispose();
    instructionData.value = null;
  }

  if (targetOffsetInCode < 0 || targetOffsetInCode >= code.length) {
    throw new Error(`Address 0x${targetAddrNum.toString(16)} is outside the .text section (runtime start: 0x${runtimeSegmentStart.toString(16)}, size: 0x${code.length.toString(16)}).`);
  }

  // const startOffsetInData = Math.max(0, targetOffsetInCode - CONTEXT_BYTES);
  // const chunkVirtualAddr = Number(runtimeSegmentStart) + startOffsetInData;
  const instructions = cs.disasm(code, runtimeTextSectionStart);
  instructionData.value = instructions;

  if (instructions.count === 0) {
    throw new Error(`No instructions found.`);
  }

  let targetIndex = -1, minAddr = bigIntMin([]), maxAddr = bigIntMax([]);
  for (let i = 0; i < instructions.count; i++) {
    const inst = instructions.get(i);
    const addr = inst.address; // BigInt
    minAddr = bigIntMin([minAddr, addr]);
    maxAddr = bigIntMax([maxAddr, addr]);
    if (targetIndex == -1 && addr > targetAddrBigInt) {
      targetIndex = i;
    }
  }

  disassemblyOutput.value += `\n Instruction start at 0x${minAddr.toString(16)}`;
  disassemblyOutput.value += `\n Instruction end at 0x${maxAddr.toString(16)}`;
  disassemblyOutput.value += `\n looking at 0x${targetAddrNum.toString(16)}`;

  if (targetIndex === -1) {
    throw new Error(`Could not locate instruction at or after 0x${targetAddrNum.toString(16)}.`);
  }

  const startIndex = Math.max(0, targetIndex - LINES_BEFORE);
  const endIndex = targetIndex + LINES_AFTER + 1;
  const displayInstructions = [];
  for (let i = startIndex; i < endIndex; i++) {
    const inst = instructions.get(i);
    displayInstructions.push(inst);
  }

  // Format for display
  let htmlOutput = '';
  for (const insn of displayInstructions) {
    const isTargetLine = insn.address === targetAddrBigInt;
    const offsetStr = `0x${insn.address.toString(16).padStart(8, '0')}`;
    const bytesStr = insn.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
    htmlOutput += `<span ${isTargetLine ? 'class="highlight" id="target-line"' : ''}>`;
    htmlOutput += `<span class="offset">${offsetStr}:</span> <span class="bytes">${bytesStr.padEnd(20)}</span> <span class="mnemonic">${insn.mnemonic}</span> ${insn.op_str}\n`;
    htmlOutput += `</span>`;
  }

  disassemblyOutput.value = htmlOutput;
  successMessage.value = `Showing ${displayInstructions.length} instructions around 0x${targetAddrNum.toString(16)}`;
  updateSymbolInfo(targetAddrNum);

  // Scroll the target line into view
  await nextTick();
  const targetLine = document.getElementById('target-line');
  if (targetLine) {
    targetLine.scrollIntoView({ behavior: 'auto', block: 'center' });
  }
};

const jumpToAddress = async () => {
  if (!jumpAddress.value || !analysisData.value) return;
  try {
    isLoading.value = true;
    error.value = null;
    const targetAddr = BigInt("0x" + jumpAddress.value.replace('0x', ''));
    await renderDisassemblyWindow(targetAddr);
  } catch (e) {
    error.value = e.message;
  } finally {
    isLoading.value = false;
  }
};

const analyzeCrash = async () => {
  isLoading.value = true;
  error.value = null;
  successMessage.value = null;
  disassemblyOutput.value = 'Starting analysis...';

  window.sessionStorage.faultLog = faultLog.value;
  window.sessionStorage.ldDebugLog = ldDebugLog.value;
  analysisData.value = null;

  try {
    // Parse RIP from fault log
    const ripMatch = faultLog.value.match(/RIP:\s+([0-9a-fA-Fx]+)/);
    if (!ripMatch) throw new Error("Could not find RIP address in the page fault message.");
    const rip = BigInt('0x' + ripMatch[1]);
    disassemblyOutput.value += `\nFound RIP: 0x${rip.toString(16)}`;

    // Parse memory map from LD_DEBUG
    const memoryMap = [];
    const ldLines = ldDebugLog.value.split('\n');

    let lastFoundPath = null;
    const foundAtRegex = /found at '(.*?)'/;
    const loadingObjectRegex = /loading object: (.*?) at (0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)/;

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
            static: false,
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
    if (!faultingModule) throw new Error(`Could not find a module containing the RIP address 0x${rip.toString(16)}.\n The code maybe loaded from mmap in the application.`);
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
    const elf = new elfist.ELFParser(new Uint8Array(arrayBuffer));

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

    // Store context for later use (jumping)
    analysisData.value = {
      code,
      runtimeSegmentStart: runtimeModuleOffset + BigInt(mmapLayout.vaddr),
      runtimeTextSectionStart: runtimeModuleOffset + BigInt(textSection.addr),
      runtimeModuleOffset,
      symbols: elf.symbols,
      cs: new cs.Capstone(arch, mode),
    };

    jumpAddress.value = "0x" + rip.toString(16);

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

</script>

<template>
  <div class="controls">
    <h1>Redox Crash Analyzer</h1>
    <div>
      <label for="fault-log">1. Page Fault Message</label>
      <textarea id="fault-log" v-model="faultLog" placeholder="Paste kernel log with RIP address here..."></textarea>
    </div>
    <div>
      <label for="ld-debug-log">2. LD_DEBUG Output</label>
      <textarea id="ld-debug-log" v-model="ldDebugLog"
        placeholder="Paste 'env LD_DEBUG=all ...' output here..."></textarea>
    </div>
    <div>
      <label for="sysroot-dir">3. Sysroot Directory</label>
      <div class="dir-picker">
        <span>{{ sysrootDirHandle ? sysrootDirHandle.name : 'No directory selected' }}</span>
        <button @click="selectDirectory">Select Sysroot</button>
      </div>
      <small style="opacity: 0.6;">Select the root folder containing the binaries (hint: run make mount).</small>
    </div>
    <button @click="analyzeCrash" :disabled="isLoading || !isReady">
      {{ isLoading ? 'Analyzing...' : 'Analyze Crash' }}
    </button>
  </div>

  <div class="output-view">
    <div class="status">
      <div v-if="error" class="error">{{ error }}</div>
      <div v-else-if="successMessage" class="success">{{ successMessage }}</div>
      <div v-else>Disassembly Output</div>
    </div>

    <div class="jump-controls" v-if="analysisData">
      <div class="jump-input-group">
        <input type="text" v-model="jumpAddress" placeholder="0x..." @keyup.enter="jumpToAddress" />
        <button @click="jumpToAddress">Jump</button>
      </div>
      <div class="symbol-info" v-if="currentSymbolName">{{ currentSymbolName }}</div>
    </div>

    <pre v-html="disassemblyOutput"></pre>
  </div>
</template>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}

.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}

.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}
</style>
