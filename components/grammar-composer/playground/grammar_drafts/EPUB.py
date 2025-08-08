######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_epub(CONTAINER_XML: bytes, PACKAGE_OPF: bytes, CONTENT_XHTML: bytes, NAV_DOC: bytes, EXTRA_CONTENT: bytes, CSS_FILE: bytes, IMG_FILE: bytes) -> bytes:
    """
    Assemble the final .epub (ZIP archive).  All entries are ‘stored’
    (compression method 0) to keep the helper compact and deterministic.
    """
    import struct, binascii

    def mk_entry(fname_utf8: str, data: bytes, offset: int):
        name = fname_utf8.encode('utf-8')
        crc = binascii.crc32(data) & 4294967295
        size = len(data)
        lfh = struct.pack('<IHHHHHIIIHH', 67324752, 20, 0, 0, 0, 0, crc, size, size, len(name), 0) + name + data
        cdfh = struct.pack('<IHHHHHHIIIHHHHHII', 33639248, 20, 20, 0, 0, 0, 0, crc, size, size, len(name), 0, 0, 0, 0, 0, offset) + name
        return (lfh, cdfh, len(lfh))
    files = [('mimetype', b'application/epub+zip'), ('META-INF/container.xml', CONTAINER_XML), ('OPS/package.opf', PACKAGE_OPF), ('OPS/content.xhtml', CONTENT_XHTML)]
    if NAV_DOC:
        files.append(('OPS/nav.xhtml', NAV_DOC))
    if EXTRA_CONTENT:
        files.append(('OPS/chapter2.xhtml', EXTRA_CONTENT))
    if CSS_FILE:
        files.append(('OPS/style.css', CSS_FILE))
    if IMG_FILE:
        files.append(('OPS/image.png', IMG_FILE))
    (local_parts, central_parts) = ([], [])
    off = 0
    for (fn, data) in files:
        (lfh, cdfh, consumed) = mk_entry(fn, data, off)
        local_parts.append(lfh)
        central_parts.append(cdfh)
        off += consumed
    cd = b''.join(central_parts)
    cd_size = len(cd)
    cd_offset = off
    eocd = struct.pack('<IHHHHIIH', 101010256, 0, 0, len(files), len(files), cd_size, cd_offset, 0)
    return b''.join(local_parts) + cd + eocd

######################################################################
# Grammar Rules
######################################################################

ctx.script('START', ['CONTAINER_XML', 'PACKAGE_OPF', 'CONTENT_XHTML', 'NAV_DOC', 'EXTRA_CONTENT', 'CSS_FILE', 'IMG_FILE'], build_epub)
ctx.rule('CONTAINER_XML', b'<?xml version="1.0" encoding="UTF-8"?>\n<container version="{CVER}" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">\n  <rootfiles>\n    <rootfile full-path="OPS/package.opf" media-type="application/oebps-package+xml"/>\n  </rootfiles>\n</container>')
ctx.regex('CVER', '1\\.[0-9]')
ctx.rule('PACKAGE_OPF', b'<?xml version="1.0" encoding="UTF-8"?>\n<package version="3.0" xmlns="http://www.idpf.org/2007/opf">\n  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n    <dc:identifier id="id">{UUID}</dc:identifier>\n    <dc:title>{TITLE}</dc:title>\n    <dc:language>{LANG}</dc:language>\n  </metadata>\n  <manifest>\n    <item id="main" href="content.xhtml" media-type="application/xhtml+xml"/>\n  </manifest>\n  <spine>\n    <itemref idref="main"/>\n  </spine>\n</package>')
ctx.rule('PACKAGE_OPF', b'<?xml version="1.0" encoding="UTF-8"?>\n<package version="{EPUB_VER}" xmlns="http://www.idpf.org/2007/opf">\n  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n    <dc:identifier id="id">{UUID}</dc:identifier>\n    <dc:title>{TITLE}</dc:title>\n    <dc:language>{LANG}</dc:language>\n    <meta property="dcterms:modified">2001-01-01T00:00:00Z</meta>\n  </metadata>\n  <manifest>\n    <item id="main" href="content.xhtml"   media-type="application/xhtml+xml"/>\n    <item id="nav"  href="nav.xhtml"       media-type="application/xhtml+xml" properties="nav"/>\n    <item id="c2"   href="chapter2.xhtml"  media-type="application/xhtml+xml"/>\n    <item id="css"  href="style.css"       media-type="text/css"/>\n    <item id="img"  href="image.png"       media-type="image/png"/>\n  </manifest>\n  <spine>\n    <itemref idref="main"/>\n    <itemref idref="c2" linear="no"/>\n  </spine>\n</package>')
ctx.regex('EPUB_VER', '2\\.0|3\\.[0-2]')
ctx.regex('UUID', '[0-9a-f]{8}\\-[0-9a-f]{4}\\-[1-5][0-9a-f]{3}\\-[89ab][0-9a-f]{3}\\-[0-9a-f]{12}')
ctx.regex('LANG', '[a-z]{2}(-[A-Z]{2})?')
ctx.rule('CONTENT_XHTML', b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE html>\n<html xmlns="http://www.w3.org/1999/xhtml">\n  <head>\n    <title>{TITLE}</title>\n    <meta charset="utf-8"/>\n    <link rel="stylesheet" type="text/css" href="style.css"/>\n  </head>\n  <body>\n    {BODY}\n    <img src="image.png" alt="img"/>\n  </body>\n</html>')
ctx.literal('NAV_DOC', b'')
ctx.rule('NAV_DOC', b'<?xml version="1.0" encoding="UTF-8"?>\n<html xmlns="http://www.w3.org/1999/xhtml">\n  <head><title>Navigation</title></head>\n  <body>\n    <nav epub:type="toc" id="toc">\n      <ol>\n        <li><a href="content.xhtml">{TITLE}</a>\n          <ol>\n            <li><a href="chapter2.xhtml">Extra</a></li>\n          </ol>\n        </li>\n      </ol>\n    </nav>\n  </body>\n</html>')
ctx.literal('EXTRA_CONTENT', b'')
ctx.rule('EXTRA_CONTENT', b'<?xml version="1.0" encoding="UTF-8"?>\n<html xmlns="http://www.w3.org/1999/xhtml">\n  <head><title>{TITLE}</title></head>\n  <body>\n    <h1>Extra Chapter</h1>\n    {BODY}\n  </body>\n</html>')
ctx.literal('CSS_FILE', b'')
ctx.rule('CSS_FILE', b'{CSS_CONTENT}')
ctx.regex('CSS_CONTENT', '[A-Za-z0-9:;#\\-\\n ]{20,120}')
ctx.literal('IMG_FILE', b'')
ctx.bytes('IMG_FILE', 256)
ctx.rule('TITLE', b'{WORD}')
ctx.rule('TITLE', b'{WORD} {WORD}')
ctx.rule('TITLE', b'{WORD} {WORD} {WORD}')
ctx.regex('WORD', '[A-Za-z]{3,12}')
ctx.rule('BODY', b'{PARA}{BODY}')
ctx.literal('BODY', b'')
ctx.rule('PARA', b'<p>{INLINE}</p>')
ctx.rule('INLINE', b'{TEXT}')
ctx.rule('INLINE', b'<b>{TEXT}</b>')
ctx.rule('INLINE', b'<i>{TEXT}</i>')
ctx.rule('INLINE', b'{TEXT} &amp; {TEXT}')
ctx.regex('TEXT', '[A-Za-z0-9 ,.;:?!]{1,60}')
