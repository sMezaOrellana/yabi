from dissect.cstruct import ctypes, cstruct, dumpstruct, Structure


def cstruct_to_dict(structure: Structure) -> dict[str, any]:
    res = {}
    for k, v in getattr(structure, "_values").items():
        if not isinstance(v, Structure):
            res[k] = v
        else:
            res[k] = cstruct_to_dict(v)

    return res


if __name__ == '__main__':
    definitions = 'structs.h'
    contents = ''
    with open(definitions, "r") as file:
        contents = file.read()

    structs = cstruct()
    structs.load(contents)

    data = b'\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04'  # endianess
    in_addr = structs.sockaddr_in(data)
    ip = in_addr.sin_addr.s_addr
    import ipaddress
    print(in_addr)
    print(dumpstruct(structs.sockaddr_in, data))
    import json
    print(dir(structs.sockaddr_in))
    print(dir(in_addr))
    all_attributes = dir(in_addr)

    print(cstruct_to_dict(in_addr))
