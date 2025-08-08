
# these 2 rules actually are used to solve test.c
ctx.rule("START", "{HECK}THIS{STUFF}")
# ctx.int(IDENTIFIER, num_bits)
ctx.int("HECK", 32)
# ctx.bytes(IDENTIFIER, num_bytes)
ctx.bytes("STUFF", 8)
