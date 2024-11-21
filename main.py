import ctypes
import os
import argparse
from procaddressspace import Process
from pathlib import PosixPath
from util import get_address_space_layout, load_library_get_relative_addr
import myptrace
import struct
import dissect.cstruct

parser = argparse.ArgumentParser(
    description="Another binary injector, for tracing syscalls/library calls")


class UserRegsStruct(ctypes.Structure):
    """Define the register structure."""
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def hook(pid, original_data, addr):
    """Handle the breakpoint when it is hit."""
    print("Breakpoint hit!")

    regs = UserRegsStruct()
    myptrace.ptrace(myptrace.PTRACE_GETREGS, pid, None, ctypes.byref(regs))

    print("Register values:")
    print(f"RIP: {regs.rip:#x}")
    print(f"RSP: {regs.rsp:#x}")
    print(f"RAX: {regs.rax:#x}")
    print(f"RBX: {regs.rbx:#x}")
    print(f"RCX: {regs.rcx:#x}")
    print(f"RDX: {regs.rdx:#x}")
    print(f"RSI: {regs.rsi:#x}")
    print(f"RDI: {regs.rdi:#x}")
    print(f"EFLAGS: {regs.eflags:#x}")

    res = myptrace.peek_data(pid, regs.rdi)
    res = struct.pack('>Q', res)[::-1]
    print(res)


def debug(pid, original_data,  addr):
    while True:
        try:
            os.waitpid(pid, 0)
            hook(pid, original_data, addr)
            myptrace.restore_breakpoint(
                pid, addr,  original_data)

            myptrace.single_step(pid)
            os.waitpid(pid, 0)
            original_data = myptrace.set_breakpoint(pid, addr)
            myptrace.cont(pid)

        except:
            myptrace.detach(pid)
            break


if __name__ == '__main__':

    parser.add_argument('--pid', type=int, help="pid of process to hook")

    parser.add_argument(
        '--function',
        type=str,
        help="function or list of functions to trace e.g `libc:open,libc:read`"
    )

    parser.add_argument(
        '--function_param_types',
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

    address_space = get_address_space_layout(args.pid)
    process = Process(address_space)

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

        myptrace.attach(args.pid)
        original_data = myptrace.set_breakpoint(args.pid, func_addr)
        myptrace.cont(args.pid)

        debug(args.pid, original_data, func_addr)

    # print(repr(address_space))
