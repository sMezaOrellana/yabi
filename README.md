# Binary Injector with Tracing Capability [WIP]

## Overview

This Python CLI implements a binary injection and tracing tool designed to hook and trace system calls or library function calls. 
The utility leverages `ptrace` to debug and interact with a target process. 
It sets breakpoints, reads registers, and inspects memory to trace and analyze function invocations. You can define the libary call you want to hook and pass the definition, in order to dump the structs in a human readable way.

---

## Features
1. **Hooking into Processes:**
   - Attaches to a running process using its Process ID (PID).
   - Sets breakpoints on specified library / system calls (TODO).

2. **Dynamic Function Address Resolution:**
   - Resolves the relative address of a function in the process's memory space, accounting for shared libraries.

3. **Custom Parameter Parsing:**
   - Supports defining function parameter types to analyze the arguments passed to the hooked functions.

4. **Process Memory Inspection:**
   - Reads and inspects memory at specific locations pointed to by registers or function arguments.

---

## Requirements

- **Python Libraries:**
  - `ctypes`
  - `argparse`
  - `struct`
  - `dissect.cstruct`
  - `myptrace` (custom module for managing `ptrace` functionality)
  - `procaddressspace` (module for address space analysis)
  - `util` (helper functions for library loading and address calculation)

- **Operating System:**
  - Linux (due to reliance on `ptrace` system calls).
  - Android

---

## How It Works

1. **Command-Line Arguments:**
   The tool accepts the following arguments:
   - `--pid`: PID of the process to hook.
   - `--function`: Function(s) to trace, in the format `library:function_name`.
   - `--function_param_types`: Parameter types of the function(s) to trace (e.g., `const char *:pathname, int:flags`).
   - `--function_param_structs_path`: Path to a file defining complex parameter structures.
   <!-- - `command`: The command to execute post-function invocation. -->

2. **Address Space Layout:**
   - Fetches and analyzes the memory map of the target process to locate the library and function addresses.

3. **Breakpoint Handling:**
   - Injects a breakpoint at the function address and saves the original instruction bytes.
   - Restores the instruction bytes after the breakpoint is hit to ensure the process execution remains unaffected.

4. **Register Dumping:**
   - Captures and prints the current CPU register state when the breakpoint is triggered.

5. **Function Debugging Loop:**
   - Handles process execution using a single-stepping mechanism.
   - Continues monitoring until the debugging session ends or the user stops the tool.

---

## Example Usage

### Attaching to a Process:
```bash
python binary_injector.py --pid 1234 --function "libc:open" --function_param_types "const char *:pathname, int:flags"
```
