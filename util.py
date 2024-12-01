import ctypes
from typing import Optional, Union, Literal
from procaddressspace import ProcAddressSpace, Process
from pathlib import PosixPath
from dissect.cstruct import Structure


def cstruct_to_dict(structure: Structure) -> dict[str, any]:
    res = {}
    for k, v in getattr(structure, "_values").items():
        if not isinstance(v, Structure):
            res[k] = v
        else:
            res[k] = cstruct_to_dict(v)

    return res


class RegsStruct__x86_64(ctypes.Structure):
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

    # TODO: check number int is less than len(mapping)
    # TODO: add support for arguments on the stack
    def get_argument(self, number: int):
        _mapping = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        return getattr(self, _mapping[number])

    def print_regs(self):
        """Print the register values."""
        for field, value in self._fields_:
            print(f"{field}: {hex(getattr(self, field))}")


def get_address_space_layout(
        pid: Union[int, Literal["self"]]) -> Optional[ProcAddressSpace]:

    # TODO: this is just a constructor
    maps_file = f"/proc/{pid}/maps"
    mapping = None

    with open(maps_file, "r") as f:
        mapping = f.readlines()

    if mapping:
        return ProcAddressSpace(mapping)
    else:
        return None


def load_library_get_relative_addr(process: Process,
                                   lib_path: PosixPath,
                                   function_name: str) -> int:
    # Load the shared library
    lib = ctypes.CDLL(lib_path)

    # Get the function from the library
    func = getattr(lib, function_name)

    # Print function address
    func_address = ctypes.cast(func, ctypes.c_void_p).value

    # Get the base address of the loaded library (we need to read from /proc)
    _, self_base_address = process.get_address_file(lib_path)

    return func_address - self_base_address


def format_hex(b):
    return " ".join(f"{byte:02x}" for byte in b)
