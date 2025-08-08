def bool_as_go(b: bool) -> str:
    return str(b).lower()

def escape_double_quotes(string):
    return string.replace('\\','\\\\').replace('"',r'\"')

def hex_escape(string):
    return "{}".format(''.join(['\\x{:02x}'.format(ord(c))[-2:] for c in string]))

