######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_zip(CONTAINER_XML: bytes, DISPLAY_OPTIONS_XML: bytes, OPF_XML: bytes, NAV_XHTML: bytes, CHAPTER_XHTML: bytes, CSS_FILE: bytes, JS_FILE: bytes, SVG_FILE: bytes, PNG_FILE: bytes, MP3_FILE: bytes, OTF_FILE: bytes) -> bytes:
    """
    Construct a valid ZIP-based iBooks container.
    Compression heuristic:
      • mimetype always STORED.
      • other files → STORED if len%3==0 else DEFLATE (raw).
    This deterministic rule yields mixed compression without RNG.
    """
    import struct, binascii, zlib
    filelist = [('mimetype', b'application/x-ibooks+zip'), ('META-INF/container.xml', CONTAINER_XML), ('META-INF/com.apple.ibooks.display-options.xml', DISPLAY_OPTIONS_XML), ('OEBPS/content.opf', OPF_XML), ('OEBPS/nav.xhtml', NAV_XHTML), ('OEBPS/chapter.xhtml', CHAPTER_XHTML), ('OEBPS/style.css', CSS_FILE), ('OEBPS/script.js', JS_FILE), ('OEBPS/vector.svg', SVG_FILE), ('OEBPS/image.png', PNG_FILE), ('OEBPS/audio.mp3', MP3_FILE), ('OEBPS/font.otf', OTF_FILE)]
    (lfh_blob, cd_blob) = (b'', b'')
    offset = 0
    for (name, raw) in filelist:
        name_b = name.encode('utf-8')
        if name == 'mimetype' or len(raw) % 3 == 0:
            (method, comp) = (0, raw)
        else:
            method = 8
            comp = zlib.compress(raw, 6)[2:-4]
        crc = binascii.crc32(raw) & 4294967295
        clen = len(comp)
        ulen = len(raw)
        lfh = struct.pack('<IHHHHHIIIHH', 67324752, 20, 0, method, 0, 0, crc, clen, ulen, len(name_b), 0) + name_b
        lfh_blob += lfh + comp
        cd = struct.pack('<IHHHHHHIIIHHHHHII', 33639248, 788, 20, 0, method, 0, 0, crc, clen, ulen, len(name_b), 0, 0, 0, 0, 0, offset) + name_b
        cd_blob += cd
        offset += len(lfh) + clen
    eocd = struct.pack('<IHHHHIIH', 101010256, 0, 0, len(filelist), len(filelist), len(cd_blob), len(lfh_blob), 0)
    return lfh_blob + cd_blob + eocd

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{IBOOKS_ZIP}')
ctx.regex('WORD', '[A-Za-z0-9]{1,12}')
ctx.regex('LANG_CODE', '[a-z]{2}')
ctx.rule('TEXT', b'{WORD}')
ctx.rule('TEXT', b'{WORD} {WORD}')
ctx.rule('TEXT', b'{WORD} {WORD} {WORD}')
ctx.rule('TEXT', b'{WORD} {WORD} {WORD} {WORD}')
ctx.rule('CONTAINER_XML', b'<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>')
ctx.rule('DISPLAY_OPTIONS_XML', b'<?xml version="1.0" encoding="UTF-8"?><display_options><platform name="*"><option name="fixed-layout">true</option></platform></display_options>')
ctx.rule('NAV_XHTML', b'<?xml version="1.0" encoding="UTF-8"?><html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><head><title>TOC</title></head><body><nav epub:type="toc"><ol><li><a href="chapter.xhtml">{TEXT}</a></li></ol></nav></body></html>')
ctx.rule('CHAPTER_XHTML', b'<?xml version="1.0" encoding="UTF-8"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>{TEXT}</title><link rel="stylesheet" href="style.css"/><script src="script.js"></script></head><body><h1>{TEXT}</h1><p>{TEXT}</p><object data="vector.svg" type="image/svg+xml"></object><audio src="audio.mp3" controls></audio></body></html>')
ctx.rule('OPF_XML', b'<?xml version="1.0" encoding="UTF-8"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="BID" prefix="ibooks: http://apple.com/ibooks/vocabulary/ibooks#"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="BID">{WORD}</dc:identifier><dc:title>{TEXT}</dc:title><dc:language>{LANG_CODE}</dc:language><dc:creator>{TEXT}</dc:creator></metadata><manifest><item id="nav"    href="nav.xhtml"     media-type="application/xhtml+xml" properties="nav"/><item id="chap"   href="chapter.xhtml" media-type="application/xhtml+xml"/><item id="css"    href="style.css"     media-type="text/css"/><item id="js"     href="script.js"     media-type="application/javascript"/><item id="svg"    href="vector.svg"    media-type="image/svg+xml"/><item id="img"    href="image.png"     media-type="image/png"/><item id="audio"  href="audio.mp3"     media-type="audio/mpeg"/><item id="font"   href="font.otf"      media-type="application/vnd.ms-opentype"/></manifest><spine><itemref idref="nav" linear="no"/><itemref idref="chap"/></spine></package>')
ctx.literal('CSS_A', b'body{margin:0;padding:0;background:#000;color:#fff}')
ctx.literal('CSS_B', b'@media (orientation:landscape){p{font-size:200%}}')
ctx.bytes('CSS_R', 80)
ctx.rule('CSS_FILE', b'{CSS_A}')
ctx.rule('CSS_FILE', b'{CSS_B}')
ctx.rule('CSS_FILE', b'{CSS_R}')
ctx.literal('JS_A', b"console.log('ibooks fuzz');")
ctx.bytes('JS_R', 60)
ctx.rule('JS_FILE', b'{JS_A}')
ctx.rule('JS_FILE', b'{JS_R}')
ctx.rule('SVG_FILE', b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text x="10" y="20">{TEXT}</text></svg>')
ctx.bytes('PNG_R', 100)
ctx.rule('PNG_FILE', b'\x89PNG\r\n\x1a\n{PNG_R}')
ctx.bytes('MP3_R', 128)
ctx.rule('MP3_FILE', b'ID3\x03\x00\x00\x00\x00\x00\x00{MP3_R}')
ctx.bytes('OTF_R', 120)
ctx.rule('OTF_FILE', b'OTTO{OTF_R}')
ctx.script('IBOOKS_ZIP', ['CONTAINER_XML', 'DISPLAY_OPTIONS_XML', 'OPF_XML', 'NAV_XHTML', 'CHAPTER_XHTML', 'CSS_FILE', 'JS_FILE', 'SVG_FILE', 'PNG_FILE', 'MP3_FILE', 'OTF_FILE'], build_zip)
