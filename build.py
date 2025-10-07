#!/usr/bin/python

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript

from __future__ import print_function
import os
import re
import sys

EXPORTED_FUNCTIONS = [
    '_malloc',
    '_free',
    '_cs_open',
    '_cs_disasm',
    '_cs_free',
    '_cs_close',
    '_cs_option',
    '_cs_group_name',
    '_cs_insn_name',
    '_cs_insn_group',
    '_cs_reg_name',
    '_cs_errno',
    '_cs_support',
    '_cs_version',
    '_cs_strerror',
    '_cs_disasm',
    '_cs_disasm_iter',
    '_cs_malloc',
    '_cs_reg_read',
    '_cs_reg_write',
    '_cs_op_count',
    '_cs_op_index',
]

EXPORTED_CONSTANTS = [
    'bindings/python/capstone/arm64_const.py',
    'bindings/python/capstone/x86_const.py',
]

# Directories
CAPSTONE_DIR = os.path.abspath("capstone")

def generateConstants():
    out = open('src/capstone-constants.js', 'w')
    out.write('const cs = {}\n')
    for path in EXPORTED_CONSTANTS:
        path = os.path.join(CAPSTONE_DIR, path)
        with open(path, 'r') as f:
            code = f.read()
            code = re.sub('\n([^#\t\r\n ])', '\ncs.\g<1>', code)
            code = re.sub('(.* = [A-Za-z_])', '# \g<1>', code)
            code = re.sub('from . import .+?\n', '', code)
            code = code.replace('#', '//')
        out.write(code)
    out.write('\nexport default cs\n')
    out.close()

def compileCapstone():
    # Clean CMake cache
    try:
        os.remove('capstone_build/CMakeCache.txt')
    except OSError:
        pass

    print('################################ CMAKE')
    # CMake
    cmd = 'cmake'
    cmd += os.path.expandvars(' -DCMAKE_TOOLCHAIN_FILE=$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake')
    cmd += ' -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF'
    cmd += ' -DCAPSTONE_X86_SUPPORT=ON'
    cmd += ' -DCAPSTONE_ARM64_SUPPORT=ON'
    cmd += ' -DCAPSTONE_BUILD_TESTS=Off'
    cmd += ' -DCAPSTONE_BUILD_CSTEST=Off'
    cmd += ' -DCMAKE_BUILD_TYPE=Release'
    
    cmd += ' -DCMAKE_C_FLAGS=\"-Wno-warn-absolute-paths\"'
    if os.name == 'nt':
        cmd += ' -G \"MinGW Makefiles\"'
    if os.name == 'posix':
        cmd += ' -G \"Unix Makefiles\"'
    cmd += ' capstone/CMakeLists.txt'
    cmd += ' -B capstone_build'
    if os.system(cmd) != 0:
        print("CMake errored")
        sys.exit(1)

    print('################################ MAKE')
    # MinGW (Windows) or Make (Linux/Unix)
    os.chdir('capstone_build')
    if os.name == 'nt':
        make = 'mingw32-make'
    if os.name == 'posix':
        make = 'make'
    if os.system(make) != 0:
        print("Make errored")
        sys.exit(1)
    os.chdir('..')

    # Compile static library to JavaScript
    print('################################ EMCC')
    exports = EXPORTED_FUNCTIONS[:]
    methods = [
        'ccall', 'getValue', 'setValue', 'writeArrayToMemory', 'UTF8ToString'
    ]
    cmd = os.path.expandvars('$EMSCRIPTEN/emcc')
    cmd += ' capstone_build/libcapstone.a'
    cmd += ' -s EXPORTED_FUNCTIONS=\"[\''+ '\', \''.join(exports) +'\']\"'
    cmd += ' -s EXPORTED_RUNTIME_METHODS=\"[\''+ '\', \''.join(methods) +'\']\"'
    cmd += ' -s ALLOW_MEMORY_GROWTH=1'
    cmd += ' -s MODULARIZE=1'
    cmd += ' -s WASM=0'
    cmd += ' -s EXPORT_ES6="1"'
    cmd += ' -o src/libcapstone.out.js'
    if os.system(cmd) != 0:
        print("Emscripten errored")
        sys.exit(1)


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")
    # Compile Capstone
    if os.name in ['nt', 'posix']:
        generateConstants()
        compileCapstone()
    else:
        print("Your operating system is not supported by this script:")
        print("Please, use Emscripten to compile Capstone manually to src/libcapstone.out.js")
