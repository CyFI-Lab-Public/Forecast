import angr


def get_string_a(state: angr.SimState, ptr: int):
    """
    Get ASCII URLs
    """
    url = ""
    while True:
        asc = state.memory.load(ptr, size=1)
        ptr += 1
        asc = state.solver.eval(asc, cast_to=int, exact=True)
        if asc == 0:
            break
        url += chr(asc)
    return url


def get_string_w(state: angr.SimState, ptr: int):
    """
    Get UTF-16 encoded URLs
    """
    url = ""
    # 1. Figure out endianness
    # The documentation for InternetOpenUrlW specifies that URLs must start with
    # ftp:, http:, or https:. Since the first character of all of these is represented
    # in UTF-16 equivalent to their ASCII values, use this information to figure out the
    # endianness.
    le = True
    val = state.memory.load(ptr, size=1)
    val = state.solver.eval(val, cast_to=int, exact=True)
    if val == 0:
        le = False
    # 2. Use endianness information to load each codepoint and append to URL string
    while True:
        cpt = load_u16(state, ptr, le)
        ptr += 2
        # 3. If UTF-16 codepoint is in 0xd800-0xe000, it is a surrogate pair.
        if cpt >= 0xD800 and cpt < 0xE000:
            hi = cpt - 0xD800
            lo = load_u16(state, ptr + 2, le) - 0xDC00
            cpt = ((hi << 10) | lo) + 0x10000
            ptr += 2
        elif cpt == 0:
            break
        # 4. Convert it to a Python string and append to URL
        url += chr(cpt)
    return url


def load_u16(state: angr.SimState, ptr: int, le: bool):
    if le:
        lv = state.memory.load(ptr, size=1)
        lv = state.solver.eval(lv, cast_to=int, exact=True)
        uv = state.memory.load(ptr + 1, size=1)
        uv = state.solver.eval(uv, cast_to=int, exact=True)
    else:
        uv = state.memory.load(ptr, size=1)
        uv = state.solver.eval(uv, cast_to=int, exact=True)
        lv = state.memory.load(ptr + 1, size=1)
        lv = state.solver.eval(lv, cast_to=int, exact=True)
    return (uv << 8) | lv
