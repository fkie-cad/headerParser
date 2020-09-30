import ctypes

HEADER_UNSUPPORTED = "unsupported"

FORCE_NONE = 0
FORCE_PE = 1


class CodeRegionData(ctypes.Structure):
    _fields_ = [("start", ctypes.c_uint64),
                ("end", ctypes.c_uint64),
                ("name", ctypes.c_char_p),
                ]


class HeaderData(ctypes.Structure):
    _fields_ = [("headertype", ctypes.c_uint8),
                ("bitness", ctypes.c_uint8),
                ("endian", ctypes.c_uint8),
                ("CPU_arch", ctypes.c_uint8),
                ("Machine", ctypes.c_char_p),
                ("regions", ctypes.POINTER(CodeRegionData)),
                ("regions_size", ctypes.c_uint64)
                ]


lib_header_parser = None
lib_header_parser_src = None


def init(src):
    """
    Init the headerparser library

    :param src: the source, where the lib is expected
    :return:
    """
    global lib_header_parser
    global lib_header_parser_src

    lib_header_parser_src = src
    lib_header_parser = ctypes.CDLL(lib_header_parser_src)

    # used in get_basic_info, no need to call it on its own
    lib_header_parser.getBasicHeaderParserInfo.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint8]
    lib_header_parser.getBasicHeaderParserInfo.restype = ctypes.POINTER(HeaderData)

    # may be used to convert the data architecture/cpu id into a readable string
    lib_header_parser.getHeaderDataArchitecture.argtypes = [ctypes.c_uint8]
    lib_header_parser.getHeaderDataArchitecture.restype = ctypes.c_char_p

    # may be used to convert the header data id into a readable string
    lib_header_parser.getHeaderDataHeaderType.argtypes = [ctypes.c_uint8]
    lib_header_parser.getHeaderDataHeaderType.restype = ctypes.c_char_p

    # automatically called in get_basic_info
    lib_header_parser.freeHeaderData.argtypes = [ctypes.POINTER(HeaderData)]
    lib_header_parser.freeHeaderData.restype = None


def get_basic_info(file_src, start=0, force=0):
    """
    Get basic info header data.

    :param file_src: the source file
    :param start: optional start offset in the file
    :param force: option force paramter, supporting FORCE_PE
    :return:
    """
    c_file_src = ctypes.c_char_p(file_src.encode("utf-8"))
    raw_result = lib_header_parser.getBasicHeaderParserInfo(c_file_src, start, force)

    if not raw_result:
        return get_initialized_hpd()

    regions = []
    for i in range(raw_result.contents.regions_size):
        region = raw_result.contents.regions[i]
        regions.append((region.name.decode('utf-8', 'backslashreplace').strip(), region.start, region.end))
        # regions.append((region.name.decode('utf-8'), region.start, region.end))

    result = {
        'headertype': raw_result.contents.headertype,
        'cpu': raw_result.contents.CPU_arch,
        'machine': raw_result.contents.Machine.decode('utf-8'),
        'endian': raw_result.contents.endian,
        'bitness': raw_result.contents.bitness,
        'regions': regions,
        'regions_size': raw_result.contents.regions_size
    }

    lib_header_parser.freeHeaderData(raw_result)

    return result


def get_initialized_hpd():
    return {
        'headertype': HEADER_UNSUPPORTED,
        'cpu': HEADER_UNSUPPORTED,
        'machine': HEADER_UNSUPPORTED,
        'endian': 0,
        'bitness': 0,
        'regions': [],
        'regions_size': 0
    }
