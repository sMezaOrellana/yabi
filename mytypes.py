import re
import ctypes

ATOMTYPE2CTYPES = {
    "uint8_t": ctypes.c_uint8,
    "char": ctypes.c_char,
    "char*": ctypes.c_char_p,
    "uint32": ctypes.c_uint32,

}


def tokenize_declaration(declaration: str) -> list[str]:
    # Define the regex pattern to match tokens
    # Match words, pointers (*), and other symbols if needed
    pattern = r'\b\w+\b|\*'

    # Find all matches in the input string
    tokens = re.findall(pattern, declaration)

    return tokens


class MyType():
    def __init__(self, c_type: str, c_structs=None):
        self.original_str = c_type
        # TODO: Add error checking and raise TokenizeException
        self.c_type = self.tokenize(c_type)
        self.c_structs = c_structs

        self.mytype = None
        self.structure = None

        # TODO: Add error checking and raise ParseException
        self.mytype = self.parse()

    def __repr__(self):
        return f"<MyType> type:{self.mytype}"

    def __str__(self):
        return f"<MyType> type:{self.mytype}"

    def tokenize(self, str) -> list[str]:
        return tokenize_declaration(str)

    def parse(self) -> bool:
        # G -> const?  struct? type pointer*
        head = 0
        struct_type = False

        if self._const(head):
            head += 1

        if self._struct(head):
            head += 1
            struct_type = True

        base_type = self.c_type[head]
        t = None

        if not struct_type:
            t = ATOMTYPE2CTYPES[base_type]
        else:
            self.structure = getattr(self.c_structs, self.c_type[head])
            t = ctypes.POINTER(ctypes.c_uint8)

        head += 1

        while (head <= len(self.c_type) - 1):
            if self._pointer(head):
                t = ctypes.POINTER(t)
                head += 1
            else:
                raise ValueError(
                    f"While parsing string: '{self.original_str}'. At position: {head} expected token: '*' received: {self.c_type[head]}")

        return t

    def _const(self, head: int) -> bool:
        return head == 0 and self.c_type[head] == 'const'

    def _struct(self, head: int) -> bool:
        return self.c_type[head] == 'struct'

    def _pointer(self, head: int) -> bool:
        return self.c_type[head] == '*'


class Parameters():
    def __init__(self, params: str):
        pass


if __name__ == '__main__':
    byte_array = b"hello, ctypes!"
    c_char_array = ctypes.create_string_buffer(byte_array)
    a = MyType("const char * ")
    print(ctypes.string_at(a.mytype(c_char_array)))
