import ctypes
import os
import sys
from typing import Callable
import signal
import struct

# Constants for ptrace
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 4
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETSIGINFO = 0x4202  # This will retrieve signal info
PTRACE_SYSCALL = 24  # To resume process and stop on syscalls
PTRACE_GETREGS = 12

# Define the ctypes function prototype for ptrace
libc = ctypes.CDLL("libc.so.6")
libc.ptrace.argtypes = [ctypes.c_int,
                        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long


def ptrace(request, pid, addr, data):
    """Wrapper for the ptrace system call."""
    return libc.ptrace(request, pid, addr, data)


def attach(pid):
    """Attach to a process using ptrace."""
    print(f"Attaching to process {pid}...")
    result = ptrace(PTRACE_ATTACH, pid, None, None)
    if result == -1:
        print(f"Error attaching to process {pid}")
        sys.exit(1)
    print(f"Attached to process {pid}")


def detach(pid):
    """Detach from a process using ptrace."""
    print(f"Detaching from process {pid}...")
    result = ptrace(PTRACE_DETACH, pid, None, None)
    if result == -1:
        print(f"Error detaching from process {pid}")
        sys.exit(1)
    print(f"Detached from process {pid}")


def peek_data(pid, addr):
    """Use ptrace to peek at a memory address in a process."""

    result = ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(
        addr), None)

    if result == -1:
        err = os.strerror(ctypes.get_errno())
        print(f"Error peeking data at address {hex(addr)}: {err}")
        sys.exit(1)

    print(f"res: {hex(result + 2**64)}")
    return result


def poke_data(pid, addr, data):
    """Use ptrace to poke data (write to a memory address in a process)."""
    result = ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(
        addr), ctypes.c_void_p(data))

    if result == -1:
        # Fetch the error code from errno
        err = os.strerror(ctypes.get_errno())
        print(f"Error poking data at address {hex(addr)}: {err}")
        sys.exit(1)


def single_step(pid):
    result = ptrace(PTRACE_SINGLESTEP, pid, None, None)
    if result == -1:
        # Fetch the error code from errno
        err = os.strerror(ctypes.get_errno())
        print(f"Error calling ptrace with flag: PTRACE_SINGLESTEP {err}")
        sys.exit(1)


def cont(pid):
    result = ptrace(PTRACE_CONT, pid, None, None)
    if result == -1:
        # Fetch the error code from errno
        err = os.strerror(ctypes.get_errno())
        print(f"Error calling ptrace with flag: PTRACE_CONT {err}")
        sys.exit(1)


def set_breakpoint(pid, addr):
    """Set a breakpoint at the given address."""
    # Read the original byte at the breakpoint address
    print(f"setting breakpoint at address: {hex(addr)}")
    original_data = peek_data(pid, addr)

    # Insert the breakpoint instruction (0xCC = INT 3)
    poke_data(pid, addr, 0xCC)
    # Continue the process until the breakpoint is hit

    return original_data


def restore_breakpoint(pid, addr, original_data):
    """Restore the original instruction at the breakpoint address."""
    poke_data(pid, addr, original_data)
