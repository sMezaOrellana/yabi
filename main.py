import ctypes
import os
import argparse
from procaddressspace import Process
from pathlib import PosixPath
from util import format_hex, get_address_space_layout, load_library_get_relative_addr, UserRegsStruct
import myptrace
import sys
import signal
from mytypes import MyType
import mywait
from dissect.cstruct import cstruct

parser = argparse.ArgumentParser(
    description="Yet Another Binary Injector, for tracing syscalls/library calls")

breakpoints = set()


def is_pointer_type(ctype):
    # hacky but it works
    return ctypes._Pointer in ctype.__mro__


def hook(pid, addr, dumps=None, process: Process = None):
    """Handle the breakpoint when it is hit."""

    regs = UserRegsStruct()
    myptrace.ptrace(myptrace.PTRACE_GETREGS, pid, None, ctypes.byref(regs))

    print(f"Adr: {hex(addr)}")
    print(f"RIP: {hex(regs.rip)}")

    if not dumps:
        return

    for index, el in enumerate(dumps):
        if not el:
            continue

        size = ctypes.sizeof(el.mytype._type_) if is_pointer_type(
            el.mytype) else ctypes.sizeof(el.mytype)

        if el.structure:
            size = len(el.structure)

        if is_pointer_type(el.mytype):
            # TODO: implement pointer following?
            # TODO: this needs to be converted to a type
            result = process.read_memory(0, regs.get_argument(index), size)

            if el.structure:
                result = el.structure(result)
            else:
                result = el.mytype._type_.from_buffer_copy(result)
        else:
            result = regs.get_argument(index)
            result = el.mytype(result)

        print(result)


BREAKPOINT_INSTUCTION = b'\xCC'


def debug(pid, addr, dumps, process):
    myptrace.attach(pid)

    original_data = process.read_memory(pid, addr, 1)
    process.write_memory(pid, addr, BREAKPOINT_INSTUCTION)
    breakpoints.add(addr)
    myptrace.cont(pid)

    while True:
        try:

            try:
                mywait.mywait(pid, signal.SIGTRAP)

            except ValueError:
                regs = UserRegsStruct()
                myptrace.ptrace(myptrace.PTRACE_GETREGS, pid,
                                None, ctypes.byref(regs))

                print(hex(regs.rip))
                print(format_hex(process.read_memory(pid, regs.rip, 20)))
                break

            hook(pid, addr, dumps, process)

            process.write_memory(pid, addr, original_data)
            breakpoints.remove(addr)

            regs = UserRegsStruct()
            myptrace.ptrace(myptrace.PTRACE_GETREGS, pid,
                            None, ctypes.byref(regs))

            next_instr = regs.rip

            myptrace.ptrace(myptrace.PTRACE_SETREGS, pid,
                            None, ctypes.byref(regs))

            myptrace.single_step(pid)
            mywait.mywait(pid, signal.SIGTRAP)

            process.read_memory(pid, next_instr, 1)
            process.write_memory(pid, addr, BREAKPOINT_INSTUCTION)

            breakpoints.add(addr)
            myptrace.cont(pid)

        except KeyboardInterrupt:
            os.kill(pid, signal.SIGTRAP)
            os.waitpid(pid, 0)

            if addr in breakpoints:
                print(f"Removing breakpoint: {addr}")
                process.write_memory(pid, addr, original_data)

            myptrace.detach(pid)
            sys.exit(0)


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
        help="definition of function(s) parameters to trace e.g `const char *, int, mode_t`"
    )

    parser.add_argument(
        '--function_defs_structs',
        type=str,
        help="path to file containing parameters type definitions e.g `rel_structs.h`"
    )

    parser.add_argument(
        'command',
        nargs=argparse.REMAINDER,
        help="The command to execute after --function."
    )

    args = parser.parse_args()
    missing_args = set()

    if not args.pid:
        missing_args.add("--pid")

    if not args.function:
        missing_args.add("--function")

    if not args.function_defs:
        missing_args.add("--function_defs")

    # if not args.function_defs_structs:
    #     missing_args.add("--function_defs_structs")

    if len(missing_args) != 0:
        err = "The following arguments are missing `{args}`".format(
            args=','.join(missing_args))

        raise ValueError(err)

    address_space = get_address_space_layout(args.pid)
    process = Process(address_space, args.pid)

    function = args.function

    structs = None

    if definitions := args.function_defs_structs:
        contents = ''
        with open(definitions, "r") as file:
            contents = file.read()

        structs = cstruct()
        structs.load(contents)

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

        types = [MyType(param, structs) if param !=
                 '_' else None for param in function_defs]

        debug(args.pid, func_addr, types, process)
