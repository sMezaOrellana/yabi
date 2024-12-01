# Binary Injector with Tracing Capability [WIP]

## Overview

YAPD, or yet another programatic debugger allows us to specify:
- process
- shared object & function
- function prototype
- struct definitions (if needed)

and it will dump the function parameters whenever the function is called by a process. The program can be called as follows:
```bash
python3 ./main.py --function libc.so.6:connect --function_defs_structs ./structs.h --function_defs "uint32, struct sockaddr_in, _" 
--pid 687253
```

The output produced would look something like

```json
{
  "libc.so.6:connect": {
    "socket": 3,
    "addr": {
      "sa_family_t": 2,
      "in_port": 8080,
      "sin_addr": {
      "s_addr": "127.0.0.1"
      }
    }
  }
}
```

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

```bash
python3 ./main.py --function libc.so.6:connect --function_defs_structs ./structs.h --function_defs "uint32, struct sockaddr_in, _" 
--pid 687253
```

