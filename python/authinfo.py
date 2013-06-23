from ctypes import cdll, Structure, POINTER, cast, byref, create_string_buffer
from ctypes import c_char, c_char_p, c_int, c_uint, c_bool, c_void_p, c_size_t
from ctypes.util import find_library

from __init__ import libauthinfo_interface


__all__ = ['AuthinfoError', 'AuthinfoParseError', 'AuthinfoEntry', 'query']

class authinfo_parse_entry_t(Structure):
    _fields_ = [('host', POINTER(c_char)),
                ('protocol', POINTER(c_char)),
                ('user', POINTER(c_char)),
                ('password', c_void_p),
                ('force', c_bool)]

class authinfo_parse_error_t(Structure):
    _fields_ = [('line', c_uint),
                ('column', c_uint),
                ('type', c_int)]

libc = cdll.LoadLibrary(find_library('c'))
libauthinfo = cdll.LoadLibrary('libauthinfo.so.%d' % libauthinfo_interface)

free = libc.free
free.restype = None
free.argtypes = [c_void_p]

authinfo_init = libauthinfo.authinfo_init
authinfo_init.restype = c_int
authinfo_init.argtypes = []

authinfo_strerror = libauthinfo.authinfo_strerror
authinfo_strerror.restype = c_char_p
authinfo_strerror.argtypes = [c_int]

authinfo_parse_strerror = libauthinfo.authinfo_parse_strerror
authinfo_parse_strerror.restype = c_char_p
authinfo_parse_strerror.argtypes = [c_int]

authinfo_find_file = libauthinfo.authinfo_find_file
authinfo_find_file.restype = c_int
authinfo_find_file.argtypes = [POINTER(c_char_p)]

authinfo_read_file = libauthinfo.authinfo_read_file
authinfo_read_file.restype = c_int
authinfo_read_file.argtypes = [c_char_p, c_char_p, POINTER(c_size_t)]

authinfo_simple_query = libauthinfo.authinfo_simple_query
authinfo_simple_query.restype = c_int
authinfo_simple_query.argtypes = [c_char_p, c_size_t,
                                  c_char_p, c_char_p, c_char_p,
                                  POINTER(authinfo_parse_entry_t),
                                  POINTER(authinfo_parse_error_t)]

authinfo_parse_entry_free = libauthinfo.authinfo_parse_entry_free
authinfo_parse_entry_free.restype = None
authinfo_parse_entry_free.argtypes = [POINTER(authinfo_parse_entry_t)]

authinfo_password_extract = libauthinfo.authinfo_password_extract
authinfo_password_extract.restype = c_int
authinfo_password_extract.argtypes = [c_void_p, POINTER(c_char_p)]


class AuthinfoError(Exception):
    __slots__ = ['type', 'msg']

    AUTHINFO_OK                    = 0
    AUTHINFO_EACCESS               = 1
    AUTHINFO_ENOENT                = 2
    AUTHINFO_ENOMEM                = 3
    AUTHINFO_ETOOBIG               = 4
    AUTHINFO_EUNKNOWN              = 5
    AUTHINFO_EGPGME                = 6
    AUTHINFO_EGPGME_DECRYPT_FAILED = 7
    AUTHINFO_EGPGME_BAD_PASSPHRASE = 8
    AUTHINFO_EGPGME_BAD_BASE64     = 9
    AUTHINFO_ENOGPGME              = 10
    AUTHINFO_ENOMATCH              = 11
    AUTHINFO_EPARSE                = 12

    def __init__(self, type):
        super(AuthinfoError, self).__init__()

        self.type = type
        self.message = authinfo_strerror(type)

    def __str__(self):
        return self.message


class AuthinfoParseError(Exception):
    __slots__ = ['type', 'line', 'column', 'msg']

    AUTHINFO_PET_NO_ERROR                  = 0
    AUTHINFO_PET_MISSING_HOST              = 1
    AUTHINFO_PET_MISSING_VALUE             = 2
    AUTHINFO_PET_VALUE_TOO_LONG            = 3
    AUTHINFO_PET_BAD_VALUE                 = 4
    AUTHINFO_PET_BAD_KEYWORD               = 5
    AUTHINFO_PET_DUPLICATED_KEYWORD        = 6
    AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN = 7
    AUTHINFO_PET_UNSUPPORTED_ESCAPE        = 8

    def __init__(self, c_error):
        super(AuthinfoParseError, self).__init__()

        self.type = c_error.type
        self.line = c_error.line
        self.column = c_error.column
        self.message = authinfo_parse_strerror(c_error.type)

    def __str__(self):
        return '%s (line %d, column %d)' % (self.message, self.line, self.column)


class AuthinfoEntry(object):
    __slots__ = ['host', 'protocol', 'user', 'password', 'force']

    def __init__(self, c_entry):
        super(AuthinfoEntry, self).__init__()

        self.host = None
        self.protocol = None
        self.user = None
        self.password = None

        if c_entry.host:
            self.host = cast(c_entry.host, c_char_p).value

        if c_entry.protocol:
            self.protocol = cast(c_entry.protocol, c_char_p).value

        if c_entry.user:
            self.user = cast(c_entry.user, c_char_p).value

        if c_entry.password:
            c_password = c_char_p()
            _handle_authinfo_result(
                authinfo_password_extract(c_entry.password, byref(c_password)))
            self.password = c_password.value

        self.force = c_entry.force

    def __str__(self):
        return '<%s host=%s protocol=%s user=%s password=%s force=%s>' % \
            (type(self).__name__,
             self.host, self.protocol, self.user, self.password, self.force)

    def is_default(self):
        return self.host is None


def _init():
    _handle_authinfo_result(authinfo_init())


def _handle_authinfo_result(ret):
    if ret == AuthinfoError.AUTHINFO_OK:
        return

    raise AuthinfoError(ret)


class AuthinfoPath(object):
    def __init__(self, path):
        self._allocated = path is None
        self._c_path = None

        if path is None:
            self._c_path = c_char_p()
            _handle_authinfo_result(authinfo_find_file(byref(self._c_path)))
        else:
            self._c_path = c_char_p(path)

    def __del__(self):
        if self._allocated and self._c_path is not None:
            free(self._c_path)

    def value(self):
        return self._c_path.value


def query(host=None, user=None, protocol=None, path=None):
    c_path = AuthinfoPath(path)

    data = create_string_buffer(1 << 16)
    data_size = c_size_t(len(data))

    _handle_authinfo_result(
        authinfo_read_file(c_path.value(), data, byref(data_size)))

    c_host = host and c_char_p(host)
    c_user = user and c_char_p(user)
    c_protocol = protocol and c_char_p(protocol)
    c_entry = authinfo_parse_entry_t()
    c_error = authinfo_parse_error_t()

    ret = authinfo_simple_query(data, data_size,
                                c_host, c_protocol, c_user,
                                byref(c_entry), byref(c_error))
    if ret == AuthinfoError.AUTHINFO_OK:
        pass
    elif ret == AuthinfoError.AUTHINFO_EPARSE:
        raise AuthinfoParseError(c_error)
    elif ret == AuthinfoError.AUTHINFO_ENOMATCH:
        return None
    else:
        _handle_authinfo_result(ret)

    try:
        return AuthinfoEntry(c_entry)
    finally:
        authinfo_parse_entry_free(byref(c_entry))


_init()
