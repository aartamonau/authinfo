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
authinfo_init.argtypes = [c_char_p]

authinfo_strerror = libauthinfo.authinfo_strerror
authinfo_strerror.restype = c_char_p
authinfo_strerror.argtypes = [c_int]

authinfo_parse_strerror = libauthinfo.authinfo_parse_strerror
authinfo_parse_strerror.restype = c_char_p
authinfo_parse_strerror.argtypes = [c_int]

authinfo_find_file = libauthinfo.authinfo_find_file
authinfo_find_file.restype = c_int
authinfo_find_file.argtypes = [POINTER(c_char_p)]

authinfo_data_from_file = libauthinfo.authinfo_data_from_file
authinfo_data_from_file.restype = c_int
authinfo_data_from_file.argtypes = [c_char_p, POINTER(c_void_p)]

authinfo_data_free = libauthinfo.authinfo_data_free
authinfo_data_free.restype = None
authinfo_data_free.argtypes = [c_void_p]

authinfo_simple_query = libauthinfo.authinfo_simple_query
authinfo_simple_query.restype = c_int
authinfo_simple_query.argtypes = [c_void_p,
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
    '''
    Represents various authinfo errors.

    Error type is stored in `AuthinfoError.type`. Human-readable error message
    is stored in `AuthinfoError.message`.

    Error Types
    -----------

    `AuthinfoError.AUTHINFO_OK`
       No error occurred

    `AuthinfoError.AUTHINFO_EACCESS`
       Authinfo file was inaccessible

    `AuthinfoError.AUTHINFO_ENOENT`
       Authinfo file could not be found

    `AuthinfoError.AUTHINFO_ENOMEM`
       Memory could not be allocated

    `AuthinfoError.AUTHINFO_EUNKNOWN`
       Unknown error occurred

    `AuthinfoError.AUTHINFO_EGPGME`
       Unexpected GPG error

    `AuthinfoError.AUTHINFO_EGPGME_DECRYPT_FAILED`
       Failed to decrypt authinfo file

    `AuthinfoError.AUTHINFO_EGPGME_BAD_PASSPHRASE`
       Bad passphrase supplied by user

    `AuthinfoError.AUTHINFO_EGPGME_BAD_BASE64`
       Malformed base64-encode password

    `AuthinfoError.AUTHINFO_ENOGPGME`
       Authinfo was built without GPG support

    `AuthinfoError.AUTHINFO_ENOMATCH`
       No matching entries found

    `AuthinfoError.AUTHINFO_EPARSE`
       Failed to parse authinfo file
    '''

    __slots__ = ['type', 'msg']

    AUTHINFO_OK                    = 0
    AUTHINFO_EACCESS               = 1
    AUTHINFO_ENOENT                = 2
    AUTHINFO_ENOMEM                = 3
    AUTHINFO_EUNKNOWN              = 4
    AUTHINFO_EGPGME                = 5
    AUTHINFO_EGPGME_DECRYPT_FAILED = 6
    AUTHINFO_EGPGME_BAD_PASSPHRASE = 7
    AUTHINFO_EGPGME_BAD_BASE64     = 8
    AUTHINFO_ENOGPGME              = 9
    AUTHINFO_ENOMATCH              = 10
    AUTHINFO_EPARSE                = 11

    def __init__(self, type):
        super(AuthinfoError, self).__init__()

        self.type = type
        self.message = authinfo_strerror(type)

    def __str__(self):
        return self.message


class AuthinfoParseError(Exception):
    '''
    Represents parsing errors.

    Error type is stored in `AuthinfoParseError.type`. Human-readable error
    description is stored in `AuthinfoParseError.message`. Line and column
    where the error occurred are stored in `AuthinfoParseError.line` and
    `AuthinfoParseError.column` respectively.

    Error types
    -----------

    `AuthinfoParseError.AUTHINFO_PET_NO_ERROR`
       No error

    `AuthinfoParseError.AUTHINFO_PET_MISSING_VALUE`
       Value was not specified for an attribute

    `AuthinfoParseError.AUTHINFO_PET_VALUE_TOO_LONG`
       Token exceeds maximum supported size

    `AuthinfoParseError.AUTHINFO_PET_BAD_VALUE`
       Invalid value provided for an attribute

    `AuthinfoParseError.AUTHINFO_PET_BAD_KEYWORD`
       Unrecognized keyword used

    `AuthinfoParseError.AUTHINFO_PET_DUPLICATED_KEYWORD`
       Duplicate or synonymous attribute

    `AuthinfoParseError.AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN`
       No matching closing double quote

    `AuthinfoParseError.AUTHINFO_PET_UNSUPPORTED_ESCAPE`
       Unsupported escape sequence used
    '''

    __slots__ = ['type', 'line', 'column', 'msg']

    AUTHINFO_PET_NO_ERROR = 0
    '''No error'''

    AUTHINFO_PET_MISSING_VALUE = 1
    '''Value was not specified for an attribute'''

    AUTHINFO_PET_VALUE_TOO_LONG = 2
    '''Token exceeds maximum supported size'''

    AUTHINFO_PET_BAD_VALUE = 3
    '''Invalid value provided for an attribute'''

    AUTHINFO_PET_BAD_KEYWORD = 4
    '''Unrecognized keyword used'''

    AUTHINFO_PET_DUPLICATED_KEYWORD = 5
    '''Duplicate or synonymous attribute'''

    AUTHINFO_PET_UNTERMINATED_QUOTED_TOKEN = 6
    '''No matching closing double quote'''

    AUTHINFO_PET_UNSUPPORTED_ESCAPE = 7
    '''Unsupported escape sequence used'''

    def __init__(self, c_error):
        super(AuthinfoParseError, self).__init__()

        self.type = c_error.type
        self.line = c_error.line
        self.column = c_error.column
        self.message = authinfo_parse_strerror(c_error.type)

    def __str__(self):
        return '%s (line %d, column %d)' % (self.message, self.line, self.column)


class AuthinfoEntry(object):
    '''
    Represents a single entry in authinfo file.

    `AuthinfoEntry.host`, `Authinfo.protocol`, `Authinfo.user`,
    `Authinfo.password` and `Authinfo.force` contain corresponding attributes
    of the entry. If some of the attributes were omitted, then the value will
    be `None` (except for `Authinfo.force` which defaults to `False`).

    '''

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
        '''
        Returns `True` if the entry is the "default" entry. I.e. "default"
        keyword was used for the entry instead of specifying concrete host name.
        '''

        return self.host is None


def _handle_authinfo_result(ret):
    if ret == AuthinfoError.AUTHINFO_OK:
        return

    raise AuthinfoError(ret)


class AuthinfoData(object):
    __slots__ = ['_data']

    def __init__(self, path):
        self._data = None

        if path is None:
            c_path = c_char_p()
            _handle_authinfo_result(authinfo_find_file(byref(c_path)))
        else:
            c_path = c_char_p(path)

        try:
            data = c_void_p()
            _handle_authinfo_result(authinfo_data_from_file(c_path, byref(data)))
            self._data = data
        finally:
            if path is None:
                free(c_path)

    def __del__(self):
        if self._data is not None:
            authinfo_data_free(self._data)

    def get_data(self):
        return self._data


def init(name=None):
    '''
    Initialize libauthinfo. `name` is a program name shown in a pinentry
    prompt. If None, sys.argv[0] is used.

    When you import authinfo for the first time, init(None) is called
    implicitly.
    '''

    if name is None:
        import sys
        name = sys.argv[0]

    c_name = c_char_p(name)
    _handle_authinfo_result(authinfo_init(c_name))


def query(host=None, user=None, protocol=None, path=None):
    '''
    Find an entry matching `host`, `user` and `protocol`. Any of these can be
    omitted. Optional `path` specifies a path to authinfo file that has to be
    used.
    '''

    data = AuthinfoData(path)

    c_host = host and c_char_p(host)
    c_user = user and c_char_p(user)
    c_protocol = protocol and c_char_p(protocol)
    c_entry = authinfo_parse_entry_t()
    c_error = authinfo_parse_error_t()

    ret = authinfo_simple_query(data.get_data(),
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


init()
