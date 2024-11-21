import ctypes
from typing import Optional, Union, Literal
from procaddressspace import ProcAddressSpace, Process
from pathlib import PosixPath


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
