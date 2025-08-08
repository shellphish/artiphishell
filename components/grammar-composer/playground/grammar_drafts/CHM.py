######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{CHM_FILE}')
ctx.rule('CHM_FILE', b'{ITSF_HEADER}{ITSP_HEADER}{PAD_TO_DIR}{DIRECTORY_CHUNK}{DATA_SECTION}')
ctx.rule('ITSF_HEADER', b'ITSF\x03\x00\x00\x00`\x00\x00\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\t\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{ITSF_PADDING}')
ctx.bytes('ITSF_PADDING', 48)
ctx.rule('ITSP_HEADER', b'ITSP\x01\x00\x00\x00T\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00{ITSP_PADDING}')
ctx.bytes('ITSP_PADDING', 64)
ctx.bytes('PAD_TO_DIR', 3916)
ctx.rule('DIRECTORY_CHUNK', b'PMGL\xe8\x0f\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00{DIR_BODY}')
ctx.bytes('DIR_BODY', 4072)
ctx.rule('DATA_SECTION', b'{HTML_SET}{RANDOM_TAIL}')
ctx.rule('HTML_SET', b'{HTML_PAGE}')
ctx.rule('HTML_SET', b'{HTML_PAGE}{HTML_SET_2}')
ctx.rule('HTML_SET_2', b'{HTML_PAGE}')
ctx.rule('HTML_SET_2', b'{HTML_PAGE}{HTML_SET_3}')
ctx.rule('HTML_SET_3', b'{HTML_PAGE}')
ctx.rule('HTML_PAGE', b'<html>{HEAD}{BODY}</html>')
ctx.literal('HEAD', b'')
ctx.rule('HEAD', b'<head>{HEAD_CONTENT}</head>')
ctx.rule('HEAD_CONTENT', b'<title>{TEXT}</title>')
ctx.rule('HEAD_CONTENT', b'<style>{CSS}</style>')
ctx.rule('HEAD_CONTENT', b'<script>{JS}</script>')
ctx.rule('BODY', b'<body>{BODY_PART}</body>')
ctx.rule('BODY_PART', b'{PARA}')
ctx.rule('BODY_PART', b'{PARA}{BODY_PART}')
ctx.rule('PARA', b'<p>{TEXT}</p>')
ctx.rule('PARA', b'<{TAG}>{TEXT}</{TAG}>')
ctx.rule('PARA', b'<img src="{SRC}" alt="{TEXT}" />')
ctx.bytes('RANDOM_TAIL', 128)
ctx.bytes('RANDOM_TAIL', 512)
ctx.bytes('RANDOM_TAIL', 2048)
ctx.bytes('RANDOM_TAIL', 8192)
ctx.bytes('RANDOM_TAIL', 16384)
ctx.regex('TAG', '[A-Za-z]{1,12}')
ctx.regex('SRC', '[A-Za-z0-9_./]{1,40}')
ctx.regex('TEXT', '[A-Za-z0-9 .,;:!?_\\-]{1,300}')
ctx.regex('CSS', '[A-Za-z0-9 :;#\\.\\-]{0,200}')
ctx.regex('JS', '[A-Za-z0-9 \\(\\);_\\-]{0,200}')
