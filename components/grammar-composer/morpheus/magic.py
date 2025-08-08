MIME_TO_NAME = {
    "application/java-vm": "JAVACLASS",
    
    # Audio
    "audio/x-wav": "WAV",
    "audio/wav": "WAV",
    "audio/aiff": "AIFF",
    "audio/x-aiff": "AIFF",
    "audio/basic": "BASICAUDIO",
    "audio/midi": "MIDI",
    "audio/x-midi": "MIDI",
    "application/x-midi": "MIDI",
    
    # CHM
    "application/vnd.ms-htmlhelp": "CHM",
    "application/chm": "CHM",
    "application/x-chm": "CHM",
    
    # Source Code
    "text/x-java-source": "JAVA",
    "text/x-c++src": "CPP",
    "text/x-groovy": "GROOVY",
    "text/x-asm": "ASM",
    "text/x-ruby": "RUBY",
    "application/javascript": "JS",
    "text/javascript": "JS",
    "application/x-javascript": "JS",
    "text/x-glsl": "GLSL",
    "text/x-lua": "LUA",
    "text/x-solidity": "SOLIDITY",
    "text/wgsl": "WGSL",
    
    # Crypto / Certificates
    "application/pkcs7-signature": "PKCS7SIGNATURE",
    "application/pkcs7-mime": "PKCS7MIME",
    "application/x-x509-ca-cert": "X509",
    "application/x-x509-cert": "X509",
    "application/x-pkcs7-certificates": "X509",
    
    # DIF
    "application/dif+xml": "DIFXML",
    
    # DWG
    "image/vnd.dwg": "DWG",
    
    # EPUB / iBooks
    "application/epub+zip": "EPUB",
    "application/x-ibooks+zip": "IBOOKS",
    
    # Executables
    "application/x-elf": "ELF",
    "application/x-sharedlib": "SHAREDLIB",
    "application/x-executable": "EXE",
    "application/x-msdownload": "EXE",
    "application/x-dosexec": "EXE",
    "application/x-coredump": "COREDUMP",
    "application/x-object": "OBJECT",
    "application/wasm": "WASM",
    
    # Feeds
    "application/atom+xml": "ATOM",
    "application/rss+xml": "RSS",
    
    # Adobe Font Metrics
    "application/x-font-adobe-metric": "AFM",
    
    # TrueType
    "application/x-font-ttf": "TTF",
    "font/ttf": "TTF",
    
    # Additional Font Formats
    "application/x-font-bdf": "BDF",
    "application/x-font-type1": "TYPE1",
    "application/x-font-type42": "TYPE42",
    
    # GDAL-related and Raster Formats
    "image/x-ozi": "OZI",
    "application/x-snodas": "SNODAS",
    "image/envisat": "ENVISAT",
    "application/fits": "FITS",
    "image/fits": "FITS",
    "image/gif": "GIF",
    "image/jp2": "JPEG2000",
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/bmp": "BMP",
    "image/x-ms-bmp": "BMP",
    "image/geotiff": "GEOTIFF",
    "image/nitf": "NITF",
    "application/x-netcdf": "NETCDF",
    "application/x-grib": "GRIB",
    "image/x-portable-pixmap": "NETPBM",
    "image/x-portable-bitmap": "NETPBM",
    "image/x-portable-graymap": "NETPBM",
    "image/x-portable-anymap": "NETPBM",
    "image/openexr": "EXR",
    
    # Additional Image Formats
    "image/x-canon-cr3": "CR3",
    "image/vnd.ms-dds": "DDS",
    "image/x-icns": "ICNS",
    "image/jbig2": "JBIG2",
    "image/x-magick-vector-graphics": "MVG",
    "image/x-portable-arbitrarymap": "PAM",
    
    # Geo and ISO
    "application/geotopic": "GEOTOPIC",
    "text/iso19139+xml": "ISO19139",
    "application/x-grib2": "GRIB2",
    "application/x-hdf": "HDF",
    
    # HTML
    "application/x-asp": "ASP",
    "application/xhtml+xml": "XHTML",
    "application/vnd.wap.xhtml+xml": "WAPXHTML",
    "text/html": "HTML",
    
    # BPG
    "image/bpg": "BPG",
    "image/x-bpg": "BPG",
    
    # Icons and Images
    "image/x-icon": "ICO",
    "image/vnd.microsoft.icon": "ICO",
    "image/vnd.wap.wbmp": "WBMP",
    "image/x-xcf": "XCF",
    "image/tiff": "TIFF",
    
    # Photoshop and WebP
    "image/vnd.adobe.photoshop": "PSD",
    "image/webp": "WEBP",
    
    # IPTC
    "text/vnd.iptc.anpa": "IPTCANPA",
    
    # ISArchive
    "application/x-isatab": "ISATAB",
    
    # iWork
    "application/vnd.apple.iwork": "IWORK",
    "application/vnd.apple.numbers": "NUMBERS",
    "application/vnd.apple.keynote": "KEYNOTE",
    "application/vnd.apple.pages": "PAGES",
    
    # Mail
    # "message/rfc822": "EMAIL",
    "message/rfc822": "SMTP",
    "application/smtp": "SMTP",
    
    # MATLAB
    "application/x-matlab-data": "MATLAB",
    
    # Mbox and Outlook
    "application/mbox": "MBOX",
    "application/vnd.ms-outlook-pst": "PST",
    "application/x-msaccess": "ACCESS",
    
    # Microsoft Formats
    "application/x-mspublisher": "PUBLISHER",
    "application/x-tika-msoffice": "OFFICE",
    "application/vnd.ms-excel": "XLS",
    "application/sldworks": "SLDWORKS",
    "application/x-tika-msworks-spreadsheet": "WPS",
    "application/vnd.ms-powerpoint": "PPT",
    "application/x-tika-msoffice-embedded; format=ole10_native": "OLEEMBEDDED",
    "application/vnd.ms-project": "MSPROJECT",
    "application/x-tika-ooxml-protected": "OOXMLPROTECTED",
    "application/msword": "DOC",
    "application/vnd.ms-outlook": "OUTLOOK",
    "application/vnd.visio": "VISIO",
    "application/vnd.ms-excel.sheet.3": "XLS",
    "application/vnd.ms-excel.sheet.2": "XLS",
    "application/vnd.ms-excel.sheet.4": "XLS",
    "application/vnd.ms-excel.workspace.3": "XLW",
    "application/vnd.ms-excel.workspace.4": "XLW",
    "application/x-tnef": "TNEF",
    "application/ms-tnef": "TNEF",
    "application/vnd.ms-tnef": "TNEF",
    "application/vnd.ms-excel.sheet.macroenabled.12": "XLSM",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": "PPTM",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": "XLTX",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
    "application/vnd.openxmlformats-officedocument.presentationml.template": "POTX",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "XLSX",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PPTX",
    "application/vnd.ms-excel.addin.macroenabled.12": "XLAM",
    "application/vnd.ms-word.document.macroenabled.12": "DOCM",
    "application/vnd.ms-excel.template.macroenabled.12": "XLTM",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": "DOTX",
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12": "PPSM",
    "application/vnd.ms-powerpoint.addin.macroenabled.12": "PPAM",
    "application/vnd.ms-word.template.macroenabled.12": "DOTM",
    "application/x-tika-ooxml": "OOXML",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": "PPSX",
    
    # MP3
    "audio/mpeg": "MP3",
    
    # MP4 / QuickTime
    "video/3gpp2": "3GPP2",
    "video/mp4": "MP4",
    "video/quicktime": "MOV",
    "audio/mp4": "M4A",
    "application/mp4": "MP4",
    "video/x-m4v": "M4V",
    "video/3gpp": "3GPP",
    "video/h264": "H264",
    
    # Additional Video Formats
    "video/av1": "AV1",
    "video/hevc": "HEVC",
    "video/x-matroska": "MKV",
    "video/x-motion-jpeg": "MJPEG",
    "video/mpeg2": "MPEG2",
    "video/x-vp8": "VP8",
    "video/x-vp9": "VP9",
    "video/webm": "WEBM",
    "video/x-msvideo": "AVI",
    
    # OpenDocument / ODF
    "application/vnd.oasis.opendocument.graphics-template": "OTG",
    "application/x-vnd.oasis.opendocument.graphics-template": "OTG",
    "application/vnd.oasis.opendocument.text": "ODT",
    "application/x-vnd.oasis.opendocument.text": "ODT",
    "application/vnd.oasis.opendocument.text-web": "OTH",
    "application/x-vnd.oasis.opendocument.text-web": "OTH",
    "application/vnd.oasis.opendocument.spreadsheet-template": "OTS",
    "application/x-vnd.oasis.opendocument.spreadsheet-template": "OTS",
    "application/vnd.oasis.opendocument.formula-template": "OTF",
    "application/x-vnd.oasis.opendocument.formula-template": "OTF",
    "application/vnd.oasis.opendocument.presentation": "ODP",
    "application/x-vnd.oasis.opendocument.presentation": "ODP",
    "application/vnd.oasis.opendocument.image-template": "OTI",
    "application/x-vnd.oasis.opendocument.image-template": "OTI",
    "application/vnd.oasis.opendocument.graphics": "ODG",
    "application/x-vnd.oasis.opendocument.graphics": "ODG",
    "application/vnd.oasis.opendocument.chart-template": "OTC",
    "application/x-vnd.oasis.opendocument.chart-template": "OTC",
    "application/vnd.oasis.opendocument.presentation-template": "OTP",
    "application/x-vnd.oasis.opendocument.presentation-template": "OTP",
    "application/vnd.oasis.opendocument.formula": "ODF",
    "application/x-vnd.oasis.opendocument.formula": "ODF",
    "application/vnd.oasis.opendocument.image": "ODI",
    "application/x-vnd.oasis.opendocument.image": "ODI",
    "application/vnd.oasis.opendocument.spreadsheet": "ODS",
    "application/x-vnd.oasis.opendocument.spreadsheet": "ODS",
    "application/vnd.oasis.opendocument.text-template": "OTT",
    "application/x-vnd.oasis.opendocument.text-template": "OTT",
    "application/vnd.oasis.opendocument.text-master": "ODM",
    "application/x-vnd.oasis.opendocument.text-master": "ODM",
    "application/vnd.oasis.opendocument.chart": "ODC",
    "application/x-vnd.oasis.opendocument.chart": "ODC",
    
    # PDF
    "application/pdf": "PDF",
    
    # Compressed
    "application/x-bzip": "BZ",
    "application/x-bzip2": "BZ2",
    "application/gzip": "GZ",
    "application/x-gzip": "GZ",
    "application/x-xz": "XZ",
    "application/x-lzma": "LZMA",
    "application/x-deflate": "DEFLATE",
    "application/x-lz4": "LZ4",
    
    # Package Formats
    "application/x-tar": "TAR",
    "application/x-tika-unix-dump": "UNIXDUMP",
    "application/java-archive": "JAR",
    "application/x-7z-compressed": "7Z",
    "application/x-archive": "AR",
    "application/x-cpio": "CPIO",
    "application/zip": "ZIP",
    
    # RAR
    "application/x-rar": "RAR",
    "application/x-rar-compressed": "RAR",
    
    # RTF
    "application/rtf": "RTF",
    "text/rtf": "RTF",
    
    # Text and Config
    # "text/plain": "TXT",
    "application/sql": "SQL",
    "text/x-sql": "SQL",
    "text/x-ini": "CONF",
    "text/x-config": "CONF",
    "application/x-wine-extension-ini": "CONF",
    "text/uri-list": "URI",
    "text/calendar": "ICS",
    "text/x-vcalendar": "ICS",
    "text/vcard": "VCF",
    "text/x-vcard": "VCF",
    "text/css": "CSS",
    "text/csv": "CSV",
    
    # Additional Document Formats
    "image/vnd.djvu": "DJVU",
    "text/markdown": "MARKDOWN",
    "multipart/related": "MHTML",
    "application/postscript": "PS",
    "text/x-rst": "RST",
    "text/x-tex": "TEX",
    "application/toml": "TOML",
    "application/yaml": "YAML",
    "text/yaml": "YAML",
    
    # FLV / Shockwave
    "video/x-flv": "FLV",
    "application/x-shockwave-flash": "SWF",
    
    # XML / JSON / Protobuf / HTTP
    "application/xml": "XML",
    "text/xml": "XML",
    "image/svg+xml": "SVG",
    "application/json": "JSON",
    "application/bson": "BSON",
    "application/x-protobuf": "PROTOBUF",
    "application/vnd.google.protobuf": "PROTOBUF",
    "application/http": "HTTP",
    "message/http": "HTTP",
    "application/http-response": "HTTPRESP",
    "application/http-request": "HTTP",
    "application/http2": "HTTP2",
    "application/x-nss": "NSS",
    "application/x-ofx": "OFX",
    "application/x-go-bin": "GOB",
    "application/x-gravity": "GRAVITY",
    "application/vnd.ms-webdav": "WEBDAV",
    "application/webdav": "WEBDAV",
    "application/x-elliptic-curve": "ELLIPTIC",
    "application/x-regexp": "REGEXP",
    "application/x-asn1": "ASN1",
    
    # Additional Data Formats
    "application/x-bplist": "BPLIST",
    "application/x-sas": "SAS",
    "application/x-spss": "SPSS",
    "application/x-stata": "STATA",
    "application/x-plist": "XPLIST",
    
    # Network/Protocol
    "application/dns": "DNS",
    "application/x-ftp": "FTP",
    "application/x-pop3": "POP3",
    "application/saml+xml": "SAML",
    "application/sdp": "SDP",
    "application/sip": "SIP",
    "application/x-zmtp": "ZMTP",
    
    # Specialized Formats
    "application/x-aff": "AFF",
    "text/x-ssa": "ASS",
    "text/x-cue": "CUE",
    "text/vnd.graphviz": "GRAPHVIZ",
    "application/vnd.iccprofile": "ICC",
    "application/mathml+xml": "MATHML",
    "chemical/x-mdl-molfile": "MOL",
    "application/x-sqlite3": "SQL",
    "application/x-vhd": "VHD",
    "text/wast": "WAST",
    "text/x-wkt": "WKT",
    "application/xslt+xml": "XSLT",
    "text/x-yara": "YARA",
    
    # FictionBook
    "application/x-fictionbook+xml": "FB2",
    
    # FLAC / OggFLAC
    # "audio/x-oggflac": "OGGFLAC",
    "audio/x-oggflac": "OGG",
    "audio/x-flac": "FLAC",
    "audio/flac": "FLAC",
    
    # Ogg Family
    # "application/kate": "KATE",
    # "application/ogg": "OGG",
    # "audio/vorbis": "OGGVORBIS",
    # "audio/x-oggpcm": "OGGPCM",
    # "video/x-oggyuv": "OGGYUV",
    # "video/x-dirac": "DIRAC",
    # "video/x-ogm": "OGM",
    # "audio/ogg": "OGGAUDIO",
    # "video/x-ogguvs": "OGGUVS",
    # "video/theora": "THEORA",
    # "video/x-oggrgb": "OGGRGB",
    # "video/ogg": "OGGVIDEO",
    "application/kate": "OGG",
    "application/ogg": "OGG",
    "audio/vorbis": "OGG",
    "audio/x-oggpcm": "OGG",
    "video/x-oggyuv": "OGG",
    "video/x-dirac": "OGG",
    "video/x-ogm": "OGG",
    "audio/ogg": "OGG",
    "video/x-ogguvs": "OGG",
    "video/theora": "OGG",
    "video/x-oggrgb": "OGG",
    "video/ogg": "OGG",
    
    # Opus and Speex
    "audio/opus": "OPUS",
    # "audio/ogg; codecs=opus": "OGGOPUS",
    "audio/ogg; codecs=opus": "OGG",
    "audio/speex": "SPEEX",
    # "audio/ogg; codecs=speex": "OGGSPEEX",
    "audio/ogg; codecs=speex": "OGG",

    ### Other formats
    "text/x-script.python": "PY",
    "image/avif": "AVIF",
    "text/x-c": "C",
    "text/x-c++": "CPP",
    "text/x-java": "JAVA",
    "text/x-php": "PHP",
    "application/zlib": "ZLIB",
    "text/x-shellscript": "SH",
    "text/x-perl": "PL",
    "text/x-makefile": "MAKEFILE",
    "application/zstd": "ZSTD",
    "image/x-tga": "TGA",
    "application/vnd.ms-opentype": "OTF",
    "font/sfnt": "SFNT",
    "image/heif": "HEIF",
    "application/x-lzip": "LZ",
    "application/x-gtar": "GTAR",
    "image/x-pcx": "PCX",
    "application/vnd.tcpdump.pcap": "PCAP",
}

ALIAS_TO_NAME = {name: name for name in MIME_TO_NAME.values()}
ALIAS_TO_NAME.update({
    "CLASS": "JAVACLASS",
    "AU": "BASICAUDIO",
    "SND": "BASICAUDIO",
    "CRT": "X509",
    "CER": "X509",
    "PEM": "X509",
    "SO": "SHAREDLIB",
    "PPM": "NETPBM",
    "PBM": "NETPBM",
    "PGM": "NETPBM",
    "PNM": "NETPBM",
    "EMAIL": "SMTP",
    "EML": "SMTP",
    "MSG": "SMTP",
    "INI": "CONF",
    "CONFIG": "CONF",
    "OGA": "OGG",
    "OGV": "OGG",
    "SOL": "SOLIDITY",
    "RB": "RUBY",
    "DIF": "DIFXML",
    "P7S": "PKCS7SIGNATURE",
    "P7M": "PKCS7MIME",
    "ANPA": "IPTCANPA",
    "DB": "SQL",
    "SQLITE": "SQL",
    "MK": "MAKEFILE",
    "MD": "MARKDOWN",
    "SPX": "SPEEX",
    "HEIC": "HEIF",
    "ASN": "ASN1",
    "JPG": "JPEG",
    "MPEGAUDIO": "MP3",
    "MPEGVIDEO": "MP4",
    "PACKET": "PCAP",
    "TRUETYPE": "TTF",
    "7ZIP": "7Z",
    "ARCHIVE": "AR",
    "BZIP": "BZ",
    "BZIP2": "BZ2",
    "GZIP": "GZ",
    "JAVASCRIPT": "JS",
    "JP2": "JPEG2000",
    "PYTHON": "PY",
    "MAT": "MATLAB",
    "PROJECT": "MSPROJECT",
    "URL": "URI",
    "POSTSCRIPT": "PS",
    "LATEX": "TEX",
    "BASH": "SH",
    "PERL": "PL",
    "LZIP": "LZ",
    "RUST": "RST",
    "MATROSKA": "MKV",
    "WEBASSEMBLY": "WASM",
    "ASSEMBLY": "ASM",
    "TIF": "TIFF",
    "GNUTAR": "TAR",
    "BITMAP": "BMP",
    "PE": "EXE",
    "ELF32": "ELF",
    "ELF64": "ELF",
    "DER": "ASN1",
})