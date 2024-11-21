from pathlib import PosixPath
from dataclasses import dataclass, asdict
import json
import sys


@dataclass
class ProcAddressSpaceEntryRegion:
    start: int
    end: int


@dataclass
class ProcAddressSpaceEntryPermissions:
    read: bool
    write: bool
    execute: bool
    shared: bool

    @classmethod
    def from_permission_string(cls, permission_str: str):
        return cls(
            read=bool(permission_str[0] == 'r'),
            write=bool(permission_str[1] == 'w'),
            execute=bool(permission_str[2] == 'x'),
            shared=bool(permission_str[3] == 's'),
        )

    def to_dict(self):
        return asdict(self)


@dataclass
class ProcAddressSpaceEntry:
    region: ProcAddressSpaceEntryRegion
    permissions: ProcAddressSpaceEntryPermissions
    pathname: PosixPath | None

    def __init__(self, line: str):
        # Split and process the input string
        separate_elements = list(filter(lambda x: x != "", line.split(" ")))
        region = separate_elements[0].split("-")
        self.region = ProcAddressSpaceEntryRegion(
            int(region[0], 16), int(region[1], 16))

        permissions = [True if char !=
                       "-" or char == "s" else False for char in separate_elements[1]]

        self.permissions = ProcAddressSpaceEntryPermissions(
            *permissions)
        self.pathname = PosixPath(
            separate_elements[5][:-1]) if separate_elements[5] != "\n" else None

    def __repr__(self):
        d = asdict(self)
        return json.dumps(d, default=str, indent=2)


@dataclass
class ProcAddressSpace():
    proc_address_space_entries: list[ProcAddressSpaceEntry]

    def __init__(self, address_space: list[str]):
        self.proc_address_space_entries: list[ProcAddressSpaceEntry] = []
        for line in address_space:
            self.proc_address_space_entries.append(ProcAddressSpaceEntry(line))

    def __repr__(self):
        return json.dumps(asdict(self), default=str, indent=2)


class Process():
    def __init__(self, proc_address_space: ProcAddressSpace):
        self.proc_address_space = proc_address_space
        self.shared_objects = {
            entry.pathname for entry in proc_address_space.proc_address_space_entries if isinstance(entry.pathname, PosixPath) and ".so" in entry.pathname.name}

    def get_address_file(self, file: PosixPath) -> (PosixPath, int):
        file = [f for f in self.shared_objects if file.name == f.name]

        if file:
            file = file[0]
        else:
            return (None, -1)

        # Python's int can handle arbitrarly large numbers
        min = sys.maxsize + 1

        # can be done in log(n) steps
        # currently done in n steps
        # it probably does not really matter
        for entry in self.proc_address_space.proc_address_space_entries:
            if entry.pathname and entry.pathname == file and entry.region.start < min:
                min = entry.region.start

        return (file, min)

    def read_memory(self, pid, address: int, size: int) -> bytes:
        mem_file = f"/proc/{pid}/mem"
        buffer = None

        with open(mem_file, "rb") as f:
            f.seek(address)
            buffer = f.read(size)

        return buffer

    def write_memory(self, pid, address: int, content: bytes):
        print(hex(address))
        mem_file = f"/proc/{pid}/mem"

        with open(mem_file, "wb") as f:
            f.seek(address)
            f.write(content)
