import ctypes
import os
import argparse
from procaddressspace import Process
from pathlib import PosixPath
from util import get_address_space_layout, load_library_get_relative_addr, UserRegsStruct
import myptrace
import struct
import sys
from mytypes import MyType
parser = argparse.ArgumentParser(
    description="Another binary injector, for tracing syscalls/library calls")


def is_pointer_type(ctype):
    return ctypes._Pointer in ctype.__mro__


def hook(pid, original_data, addr, dumps=None, process: Process = None):
    """Handle the breakpoint when it is hit."""
    print("Breakpoint hit!")

    regs = UserRegsStruct()
    myptrace.ptrace(myptrace.PTRACE_GETREGS, pid, None, ctypes.byref(regs))

    if not dumps:
        return
    print(dumps)
    print("here")
    for index, el in enumerate(dumps):
        print(f"here {index}")
        if not el:
            continue

        if is_pointer_type(el.mytype):
            size = ctypes.sizeof(el.mytype._type_)
            print(size)

            if not process:
                break

            mem_buffer = process.read_memory(0, regs.get_argument(index), size)
            print(mem_buffer)

        else:
            print(el.mytype)
            size = ctypes.sizeof(el.mytype)
            print(size)

            if not process:
                break

            r = regs.get_argument(index)

            print(r)

    print("here done")


def debug(pid, original_data, addr, dumps, process):
    while True:
        try:
            os.waitpid(pid, 0)
            hook(pid, original_data, addr, dumps, process)
            myptrace.restore_breakpoint(
                pid, addr,  original_data)

            myptrace.single_step(pid)
            os.waitpid(pid, 0)
            original_data = myptrace.set_breakpoint(pid, addr)
            myptrace.cont(pid)

        except Exception as e:
            myptrace.detach(pid)
            raise (e)
            break


if __name__ == '__main__':

    parser.add_argument('--pid', type=int, help="pid of process to hook")

    parser.add_argument(
        '--function',
        type=str,
        help="function or list of functions to trace e.g `libc:open,libc:read`"
    )

    parser.add_argument(
        '--function_defs',
        type=str,
        help="definition of function(s) parameters to trace e.g `const char *:pathname, int:flags, mode_t:mode`"
    )

    parser.add_argument(
        '--function_param_structs_path',
        type=str,
        help="path to file containing parameters type definitions e.g `rel_structs.h`"
    )

    parser.add_argument(
        'command',
        nargs=argparse.REMAINDER,
        help="The command to execute after --function."
    )

    args = parser.parse_args()

    if not args.pid:
        function_defs = args.function_defs.split(",")

        types = [MyType(param) if param !=
                 '_' else None for param in function_defs]

        print(types)
        for t in types:
            print(ctypes.sizeof(t.mytype))

        sys.exit(0)

    address_space = get_address_space_layout(args.pid)
    process = Process(address_space, args.pid)

    function = args.function

    if function:
        temp = function.rsplit(":")

        # I don't know if i like this
        path, function = PosixPath(temp[0]), temp[1]
        path, base_address = process.get_address_file(path)

        self_process = Process(get_address_space_layout('self')
                               )

        _, self_base_address = self_process.get_address_file(path)
        func_rel_addr = load_library_get_relative_addr(
            self_process, path, str(function))

        func_addr = (base_address + func_rel_addr)
        print(f"func: {function}, addr: {hex(func_addr)}")
        function_defs = args.function_defs.split(",")

        types = [MyType(param) if param !=
                 '_' else None for param in function_defs]

        print(types)
        myptrace.attach(args.pid)
        original_data = myptrace.set_breakpoint(args.pid, func_addr)
        myptrace.cont(args.pid)

        debug(args.pid, original_data, func_addr, types, process)

    # print(repr(address_space))
