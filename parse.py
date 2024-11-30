from dissect.cstruct import ctypes, cstruct, dumpstruct

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
    print(type(in_addr))
    print(len(in_addr))
    print(in_addr)
    print(dumpstruct(structs.sockaddr_in, data))
    print(type(structs))
    print(dir(structs))
    print(structs.sockaddr_in)

    print(dir(structs.sockaddr_in))
    # ctypes(structs.sockaddr_in)
