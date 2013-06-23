from ctypes import cdll
from __init__ import libauthinfo_interface

libauthinfo = cdll.LoadLibrary("libauthinfo.so.%d" % libauthinfo_interface)
