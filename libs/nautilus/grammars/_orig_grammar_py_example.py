####################
# RULE
# `ctx.rule(NONTERM: string, RHS: bytes)` adds a rule NONTERM->RHS.
####################
# IMPORTANT: All non terminals must be capitalized.

# Your grammar must include a START rule that defines the entry point for the fuzzer.
ctx.rule("START", b"<xml>{XML_CONTENT}</xml>")

# Use `.rule` to concatenate nonterminals or combine nonterminals in a context-insensitive way.
# IMPORTANT: Each occurrence of a nonterminal is regenerated independently. Even repeated symbols like {TAG}{TAG} in a `.rule` will yield different outputs in separate subtrees.
# Use {NONTERM} in the RHS to request a recursion.
ctx.rule("XML_CONTENT", b"{XML_ELEMENT}{XML_CONTENT}")

# Define alternatives as separate rules.
ctx.rule("XML_ELEMENT", b"<data-element>{DATA}</data-element>")
ctx.rule("XML_ELEMENT", b"<encoded-element>{BASE64}</encoded-element>")

ctx.rule("TAG", b"{HEX_DIGITS}")

ctx.rule("DATA", b"{BYTES}")
ctx.rule("DATA", "{BLOB}")
ctx.rule("DATA", b"{HEX_DIGITS}")


####################
# LITERAL
# `ctx.literal(NONTERM: string, value: bytes)` adds a literal (constant raw bytes) rule.
# Always use `.literal` rules when the RHS of a rule does not contain any nonterminals.
####################

ctx.literal("XML_CONTENT", b"")
ctx.literal("BLOB", b"}{\x00\x01\x02\x03")


####################
# BYTES
# `ctx.bytes(NONTERM: string, width: int)` adds a fixed-width random bytes rule.
# Use `.bytes` rules to generate random bytes with a given width.
# The width parameter specifies the number of bytes.
####################

ctx.bytes("BYTES", 4)  # -> b"\x01\x02\x03\x04"


####################
# REGEX
# `ctx.regex(NONTERM: string, regex: string)` adds a regex rule.
####################
# IMPORTANT: All regex generations must be valid Unicode characters: avoid negations (`^`) and greedy quantifiers (like `.*` or `.?`) unless you are absolutely sure they only generate Unicode characters.
# IMPORTANT: The regex generator supports a subset of regex features: literal characters, character classes (only Unicode ranges), alternation (`|`), concatenation, and grouping. 
# It also supports common repetition operators like zero-or-one (?), zero-or-more (*), one-or-more (+), and bounded repetitions ({m} or {m,n}). 
# Other features like anchors, backreferences or lookaround are NOT supported.

ctx.regex("HEX_DIGITS", "[A-Fa-f0-9]+")


####################
# HELPER FUNCTIONS
# `def helper_function(NONTERM+):` defines a helper function.
# YOU MUST DEFINE ALL YOUR HELPER FUNCTIONS BEFORE THE RESPECTIVE `.script` RULES and only if you really, really need them.
####################

# IMPORTANT: Each helper function must have at least one NONTERM parameter.
# IMPORTANT: The NONTERM parameters must match each exactly the NONTERMS of the respective invoking `.script` rules (see below).
def build_xml_element(TAG: bytes, XML_CONTENT: bytes) -> bytes:
    return b"<" + TAG + b">" + XML_CONTENT + b"</" + TAG + b">"

def encode_base64(data: bytes) -> bytes:
    # IMPORTANT: Import modules inside the function, not at the top of the file.
    # IMPORTANT: Never use global variables.
    # Any other source of information like .input() or random number generators is not available.
    import base64
    return base64.b64encode(data)


####################
# SCRIPT
# `ctx.script(NONTERM: string, RHS: List[NONTERM+], func: function)` adds a rule NONTERM->func(*RHS).
# In contrast to `.rule`, RHS is an array of nonterminals.
# Use `.script` and a helper function `func` to combine nonterminals in a context-sensitive way.
# IMPORTANT: Only use `.script` rules when it is really necessary. Never use `.script` rules when you can use `.rule` or `.literal` rules instead.
####################

# IMPORTANT: `.script` rules must have at least one NONTERM in their RHS.
ctx.script("XML_ELEMENT", ["TAG", "XML_CONTENT"], build_xml_element)

ctx.script("BASE64", ["DATA"], encode_base64)


####################
# Best Practices for Writing Good Grammars:
# - Break complex structures into small, reusable rules.
# - Always include terminating productions (base case) to prevent infinite recursion.
# - Avoid left-recursion and prefer explicit recursion to prevent infinite loops.
# - Avoid using python random number generators. Instead, use nonterminal rules like `.bytes` or `.regex`.
####################