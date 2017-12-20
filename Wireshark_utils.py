import sys
from io import StringIO


def get_show_data(packet):
    s = StringIO()
    sys.stdout = s
    packet.show()
    sys.stdout = sys.__stdout__
    full_str_list = s.getvalue().splitlines()
    return full_str_list


def get_hex_data(packet, func):
    s = StringIO()
    sys.stdout = s
    func(packet)
    sys.stdout = sys.__stdout__
    full_str_list = s.getvalue().splitlines()
    return full_str_list
