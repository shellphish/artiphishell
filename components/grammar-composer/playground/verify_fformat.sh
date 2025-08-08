#!/bin/bash

# VERIFY THAT ALL THE PACKAGES ARE INSTALLED
for package in file openssl jq python3 unzip tiffinfo protoc hexdump magika; do
  if ! command -v $package &> /dev/null; then
    echo "$package could not be found. Please install it."
    exit
  fi
done

for python_package in bson zlib; do
  if ! python3 -c "import $python_package" &> /dev/null; then
    echo "$python_package could not be found. Please install it."
    exit
  fi
done


function verify_3gpp() {
  file "$1" 2>/dev/null | grep -q "3GPP"
}
export -f verify_3gpp

function verify_3gpp2() {
  file "$1" 2>/dev/null | grep -q "3GPP2"
}
export -f verify_3gpp2

function verify_7z() {
  file "$1" 2>/dev/null | grep -q "7-zip archive"
}
export -f verify_7z

function verify_access() {
  file "$1" 2>/dev/null | grep -q "Microsoft Access"
}
export -f verify_access

function verify_afm() {
  head -n 1 "$1" 2>/dev/null | grep -q "^StartFontMetrics"
}
export -f verify_afm

function verify_aiff() {
  file "$1" 2>/dev/null | grep -q "AIFF audio"
}
export -f verify_aiff

function verify_ar() {
  file "$1" 2>/dev/null | grep -q "ar archive"
}
export -f verify_ar

function verify_asm() {
  magika -l "$1" | grep -q ": asm$" 2>/dev/null
}
export -f verify_asm

function verify_asn1() {
  openssl asn1parse -in "$1" >/dev/null 2>&1
}
export -f verify_asn1

function verify_asp() {
  grep -q -E '<%.*%>|<script.*runat="server"' "$1" 2>/dev/null
}
export -f verify_asp

function verify_atom() {
  grep -q -E '<feed.*xmlns="http://www.w3.org/2005/Atom"' "$1" 2>/dev/null
}
export -f verify_atom

function verify_avif() {
  file "$1" 2>/dev/null | grep -q "AVIF image"
}
export -f verify_avif

function verify_basicaudio() {
  file "$1" 2>/dev/null | grep -q "audio"
}
export -f verify_basicaudio

function verify_bmp() {
  file "$1" 2>/dev/null | grep -q "PC bitmap"
}
export -f verify_bmp

function verify_bpg() {
  hexdump -n 4 -e '1/1 "%02x"' "$1" 2>/dev/null | grep -q "425047fb"
}
export -f verify_bpg

function verify_bson() {
  python3 -c "import bson; bson.decode_file(open('$1', 'rb'))" >/dev/null 2>&1
}
export -f verify_bson

function verify_bz() {
  file "$1" 2>/dev/null | grep -q "bzip compressed"
}
export -f verify_bz

function verify_bz2() {
  file "$1" 2>/dev/null | grep -q "bzip2 compressed"
}
export -f verify_bz2

function verify_c() {
  magika -l "$1" | grep -q ": c$" 2>/dev/null
}
export -f verify_c

function verify_chm() {
  file "$1" 2>/dev/null | grep -q "MS Windows HtmlHelp Data"
}
export -f verify_chm

function verify_conf() {
  false
}
export -f verify_conf

function verify_coredump() {
  file "$1" 2>/dev/null | grep -q "core file"
}
export -f verify_coredump

function verify_cpio() {
  file "$1" 2>/dev/null | grep -q "cpio archive"
}
export -f verify_cpio

function verify_cpp() {
    magika -l "$1" | grep -q ": cpp$" 2>/dev/null
}
export -f verify_cpp

function verify_css() {
    magika -l "$1" | grep -q ": css$" 2>/dev/null
}
export -f verify_css

function verify_csv() {
  magika -l "$1" | grep -q ": csv$" 2>/dev/null
}
export -f verify_csv

function verify_deflate() {
  python3 -c "import zlib; zlib.decompress(open('$1', 'rb').read(), -15)" >/dev/null 2>&1
}
export -f verify_deflate

function verify_difxml() {
  head -n 1 "$1" 2>/dev/null | grep -q -E '^<\?xml' &&
  grep -q 'xmlns.*\(digitalidentity\|dif\.foundation\)' "$1" 2>/dev/null
}
export -f verify_difxml

function verify_doc() {
  file "$1" 2>/dev/null | grep -q "Microsoft Office Document"
}
export -f verify_doc

function verify_docm() {
  file "$1" 2>/dev/null | grep -q "Microsoft Word" && echo "$1" | grep -q "\.docm$"
}
export -f verify_docm

function verify_docx() {
  file "$1" 2>/dev/null | grep -q "Microsoft Word 2007+"
}
export -f verify_docx

function verify_dotm() {
  file "$1" 2>/dev/null | grep -q "Microsoft Word" && echo "$1" | grep -q "\.dotm$"
}
export -f verify_dotm

function verify_dotx() {
  file "$1" 2>/dev/null | grep -q "Microsoft Word" && echo "$1" | grep -q "\.dotx$"
}
export -f verify_dotx

function verify_dwg() {
  file "$1" 2>/dev/null | grep -q "AutoCAD"
}
export -f verify_dwg

function verify_elf() {
  file "$1" 2>/dev/null | grep -q "ELF"
}
export -f verify_elf

function verify_elliptic() {
  openssl ec -in "$1" -noout >/dev/null 2>&1
}
export -f verify_elliptic

function verify_envisat() {
  head -c 8 "$1" 2>/dev/null | grep -q "ENVISAT"
}
export -f verify_envisat

function verify_epub() {
  file "$1" 2>/dev/null | grep -q "EPUB"
}
export -f verify_epub

function verify_exe() {
  file "$1" 2>/dev/null | grep -q "PE32 executable"
}
export -f verify_exe

function verify_exr() {
  file "$1" 2>/dev/null | grep -q "OpenEXR image data"
}
export -f verify_exr

function verify_fb2() {
  head -n 1 "$1" 2>/dev/null | grep -q -E '^<\?xml' &&
  grep -q '<FictionBook' "$1" 2>/dev/null
}
export -f verify_fb2

function verify_fits() {
  file "$1" 2>/dev/null | grep -q "FITS"
}
export -f verify_fits

function verify_flac() {
  file "$1" 2>/dev/null | grep -q "FLAC audio"
}
export -f verify_flac

function verify_flv() {
  file "$1" 2>/dev/null | grep -q "Macromedia Flash Video"
}
export -f verify_flv

function verify_geotiff() {
  file "$1" 2>/dev/null | grep -q "TIFF" && tiffinfo "$1" 2>/dev/null | grep -q "GeoTIFF"
}
export -f verify_geotiff

function verify_geotopic() {
  head -n 1 "$1" 2>/dev/null | grep -q "^<?xml" 2>/dev/null &&
  grep -q -E 'xmlns(:[a-zA-Z0-9]+)?="http(s)?://www\.opengis\.net/gml' "$1" 2>/dev/null
}
export -f verify_geotopic

function verify_gif() {
  file "$1" 2>/dev/null | grep -q "GIF image"
}
export -f verify_gif

function verify_gob() {
  hexdump -n 3 -e '3/1 "%c"' "$1" 2>/dev/null | grep -q "gob"
}
export -f verify_gob

function verify_gravity() {
  # First check for an XML file containing gravity settings
  (head -n 1 "$1" 2>/dev/null | grep -q "^<?xml" 2>/dev/null && 
   grep -q -E '<gravity[^>]*>' "$1" 2>/dev/null) ||
  # Or check for gravity settings in non-XML format
  head -n 1 "$1" 2>/dev/null | grep -q -E '(^|[^a-zA-Z0-9_-])gravity *= *[0-9.-]+' 2>/dev/null
}
export -f verify_gravity

function verify_grib() {
  file "$1" 2>/dev/null | grep -q "GRIB"
}
export -f verify_grib

function verify_grib2() {
  file "$1" 2>/dev/null | grep -q "GRIB2"
}
export -f verify_grib2

function verify_groovy() {
  magika -l "$1" | grep -q ": groovy$" 2>/dev/null
}
export -f verify_groovy

function verify_gtar() {
  file "$1" 2>/dev/null | grep -q "GNU tar archive"
}
export -f verify_gtar

function verify_gz() {
  file "$1" 2>/dev/null | grep -q "gzip compressed"
}
export -f verify_gz

function verify_h264() {
  file "$1" 2>/dev/null | grep -q "H.264"
}
export -f verify_h264

function verify_hdf() {
  file "$1" 2>/dev/null | grep -q "Hierarchical Data Format"
}
export -f verify_hdf

function verify_heif() {
  file "$1" 2>/dev/null | grep -q "HEIF"
}
export -f verify_heif

function verify_html() {
  magika -l "$1" | grep -q ": html$" 2>/dev/null
}
export -f verify_html

function verify_http() {
  head -n 1 "$1" 2>/dev/null | grep -q -E "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) .+ HTTP/[0-9]" 2>/dev/null
}
export -f verify_http

function verify_http2() {
  hexdump -n 24 -e '24/1 "%02x"' "$1" 2>/dev/null | grep -q "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
}
export -f verify_http2

function verify_httpresp() {
  head -n 1 "$1" 2>/dev/null | grep -q -E "^HTTP/[0-9]"
}
export -f verify_httpresp

function verify_ibooks() {
  file "$1" 2>/dev/null | grep -q "Apple iBooks Author" || unzip -l "$1" 2>/dev/null | grep -q "META-INF/com.apple.ibooks.display-options.xml"
}
export -f verify_ibooks

function verify_ico() {
  file "$1" 2>/dev/null | grep -q "MS Windows icon"
}
export -f verify_ico

function verify_ics() {
  magika -l "$1" | grep -q ": ics$" 2>/dev/null
}
export -f verify_ics

function verify_iptcanpa() {
  grep -q -E 'IPTC|International Press Telecommunications Council' "$1" 2>/dev/null ||
  strings "$1" 2>/dev/null | grep -q -E '\<IPTC\>' 
}
export -f verify_iptcanpa

function verify_isatab() {
  head -n 1 "$1" 2>/dev/null | grep -q "^INVESTIGATION" 2>/dev/null && 
  grep -q -E "Investigation (Identifier|Title|Description)" "$1" 2>/dev/null
}
export -f verify_isatab

function verify_iso19139() {
  grep -q -E '<gmd:MD_Metadata|xmlns:gmd="http://www\.isotc211\.org/2005/gmd"' "$1" 2>/dev/null
}
export -f verify_iso19139

function verify_iwork() {
  file "$1" 2>/dev/null | grep -q "Apple iWork" || unzip -l "$1" 2>/dev/null | grep -q "Index/Document.iwa"
}
export -f verify_iwork

function verify_jar() {
  file "$1" 2>/dev/null | grep -q "Java archive" || unzip -l "$1" 2>/dev/null | grep -q "META-INF/MANIFEST.MF"
}
export -f verify_jar

function verify_java() {
  magika -l "$1" | grep -q ": java$" 2>/dev/null
}
export -f verify_java

function verify_javaclass() {
  file "$1" 2>/dev/null | grep -q "Java class"
}
export -f verify_javaclass

function verify_jpeg() {
  file "$1" 2>/dev/null | grep -q "JPEG image"
}
export -f verify_jpeg

function verify_jpeg2000() {
  file "$1" 2>/dev/null | grep -q "JPEG 2000"
}
export -f verify_jpeg2000

function verify_js() {
  magika -l "$1" | grep -q ": javascript$" 2>/dev/null
}
export -f verify_js

function verify_json() {
  jq . "$1" >/dev/null 2>&1
}
export -f verify_json

function verify_keynote() {
  file "$1" 2>/dev/null | grep -q "Apple Keynote" || unzip -l "$1" 2>/dev/null | grep -q "Index/Slide"
}
export -f verify_keynote

function verify_lz() {
  file "$1" 2>/dev/null | grep -q "lzip compressed"
}
export -f verify_lz

function verify_lzma() {
  file "$1" 2>/dev/null | grep -q "LZMA compressed"
}
export -f verify_lzma

function verify_m4a() {
  file "$1" 2>/dev/null | grep -q "ISO Media.*Apple"
}
export -f verify_m4a

function verify_m4v() {
  file "$1" 2>/dev/null | grep -q "ISO Media.*M4V"
}
export -f verify_m4v

function verify_makefile() {
  magika -l "$1" | grep -q ": makefile$" 2>/dev/null
}
export -f verify_makefile

function verify_mat() {
  file "$1" 2>/dev/null | grep -q "MATLAB"
}
export -f verify_mat

function verify_mbox() {
  head -n 1 "$1" 2>/dev/null | grep -q -E '^From .* [0-9]{4}$' 2>/dev/null
}
export -f verify_mbox

function verify_midi() {
  file "$1" 2>/dev/null | grep -q "MIDI"
}
export -f verify_midi

function verify_mov() {
  file "$1" 2>/dev/null | grep -q "QuickTime movie"
}
export -f verify_mov

function verify_mp4() {
  file "$1" 2>/dev/null | grep -q "ISO Media.*MP4"
}
export -f verify_mp4

function verify_mpegaudio() {
  file "$1" 2>/dev/null | grep -q "MPEG.*audio"
}
export -f verify_mpegaudio

function verify_netcdf() {
  file "$1" 2>/dev/null | grep -q "NetCDF"
}
export -f verify_netcdf

function verify_netpbm() {
  file "$1" 2>/dev/null | grep -q -E "Netpbm|PBM|PGM|PPM"
}
export -f verify_netpbm

function verify_nitf() {
  head -c 4 "$1" 2>/dev/null | grep -q "NITF"
}
export -f verify_nitf

function verify_nss() {
  file "$1" 2>/dev/null | grep -q "NSS.*Certificate"
}
export -f verify_nss

function verify_numbers() {
  file "$1" 2>/dev/null | grep -q "Apple Numbers" || unzip -l "$1" 2>/dev/null | grep -q "Index/Tables"
}
export -f verify_numbers

function verify_object() {
  file "$1" 2>/dev/null | grep -q "object file"
}
export -f verify_object

function verify_odc() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*chart"
}
export -f verify_odc

function verify_odf() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*formula"
}
export -f verify_odf

function verify_odg() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*graphics"
}
export -f verify_odg

function verify_odi() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*image"
}
export -f verify_odi

function verify_odm() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*text-master"
}
export -f verify_odm

function verify_odp() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*presentation"
}
export -f verify_odp

function verify_ods() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*spreadsheet"
}
export -f verify_ods

function verify_odt() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*text"
}
export -f verify_odt

function verify_office() {
  file "$1" 2>/dev/null | grep -q -E "Microsoft Office|OpenDocument|LibreOffice"
}
export -f verify_office

function verify_ofx() {
  # Check for OFX header in both version 1.x (SGML-based) and 2.x (XML-based) formats
  (grep -q -E 'OFXHEADER:[0-9]{3}' "$1" 2>/dev/null) || 
  (grep -q -E '<\?OFX OFXHEADER="[0-9]{3}"' "$1" 2>/dev/null) ||
  (grep -q -E '<OFX>' "$1" 2>/dev/null && grep -q -E '<SIGNONMSGSRQ|<SIGNONMSGSRS' "$1" 2>/dev/null)
}
export -f verify_ofx

function verify_ogg() {
  file "$1" 2>/dev/null | grep -q "Ogg data"
}
export -f verify_ogg

function verify_oleembedded() {
  file "$1" 2>/dev/null | grep -q "OLE.*Compound Document"
}
export -f verify_oleembedded

function verify_ooxml() {
  unzip -l "$1" 2>/dev/null | grep -q "[Content_Types].xml"
}
export -f verify_ooxml

function verify_ooxmlprotected() {
  unzip -l "$1" 2>/dev/null | grep -q "encryption.xml"
}
export -f verify_ooxmlprotected

function verify_opus() {
  file "$1" 2>/dev/null | grep -q "Opus audio"
}
export -f verify_opus

function verify_otc() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*chart-template"
}
export -f verify_otc

function verify_otf() {
  file "$1" 2>/dev/null | grep -q "OpenType font"
}
export -f verify_otf

function verify_otg() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*graphics-template"
}
export -f verify_otg

function verify_oth() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*text-web"
}
export -f verify_oth

function verify_oti() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*image-template"
}
export -f verify_oti

function verify_otp() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*presentation-template"
}
export -f verify_otp

function verify_ots() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*spreadsheet-template"
}
export -f verify_ots

function verify_ott() {
  unzip -l "$1" 2>/dev/null | grep -q "mimetype.*text-template"
}
export -f verify_ott

function verify_outlook() {
  file "$1" 2>/dev/null | grep -q "Microsoft Outlook"
}
export -f verify_outlook

function verify_ozi() {
  grep -q -E 'OziExplorer|Map Data File' "$1" 2>/dev/null
}
export -f verify_ozi

function verify_pages() {
  file "$1" 2>/dev/null | grep -q "Apple Pages" || unzip -l "$1" 2>/dev/null | grep -q "Index/Document.iwa"
}
export -f verify_pages

function verify_pcap() {
  file "$1" 2>/dev/null | grep -q -E "pcap capture file|tcpdump capture file"
}
export -f verify_pcap

function verify_pcx() {
  file "$1" 2>/dev/null | grep -q "PCX"
}
export -f verify_pcx

function verify_pdf() {
  file "$1" 2>/dev/null | grep -q "PDF document"
}
export -f verify_pdf

function verify_php() {
  magika -l "$1" | grep -q ": php$" 2>/dev/null || grep -q '^<?php' "$1" 2>/dev/null
}
export -f verify_php

function verify_pkcs7mime() {
  file "$1" 2>/dev/null | grep -q "PKCS7" || grep -q "Content-Type: application/pkcs7-mime" "$1" 2>/dev/null
}
export -f verify_pkcs7mime

function verify_pkcs7signature() {
  file "$1" 2>/dev/null | grep -q "PKCS7" || grep -q "Content-Type: application/pkcs7-signature" "$1" 2>/dev/null
}
export -f verify_pkcs7signature

function verify_pl() {
  magika -l "$1" | grep -q ": perl$" 2>/dev/null
}
export -f verify_pl

function verify_png() {
  file "$1" 2>/dev/null | grep -q "PNG image"
}
export -f verify_png

function verify_potx() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint" && echo "$1" | grep -q "\.potx$"
}
export -f verify_potx

function verify_ppam() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint" && echo "$1" | grep -q "\.ppam$"
}
export -f verify_ppam

function verify_ppsm() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint" && echo "$1" | grep -q "\.ppsm$"
}
export -f verify_ppsm

function verify_ppsx() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint" && echo "$1" | grep -q "\.ppsx$"
}
export -f verify_ppsx

function verify_ppt() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint"
}
export -f verify_ppt

function verify_pptm() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint" && echo "$1" | grep -q "\.pptm$"
}
export -f verify_pptm

function verify_pptx() {
  file "$1" 2>/dev/null | grep -q "Microsoft PowerPoint 2007+"
}
export -f verify_pptx

function verify_project() {
  file "$1" 2>/dev/null | grep -q "Microsoft Project" || grep -q "<Project" "$1" 2>/dev/null
}
export -f verify_project

function verify_protobuf() {
  protoc --decode_raw < "$1" >/dev/null 2>&1
}
export -f verify_protobuf

function verify_psd() {
  file "$1" 2>/dev/null | grep -q "Adobe Photoshop"
}
export -f verify_psd

function verify_pst() {
  file "$1" 2>/dev/null | grep -q "Microsoft Outlook Personal Folders"
}
export -f verify_pst

function verify_publisher() {
  file "$1" 2>/dev/null | grep -q "Microsoft Publisher"
}
export -f verify_publisher

function verify_py() {
  magika -l "$1" | grep -q ": python$" 2>/dev/null
}
export -f verify_py

function verify_rar() {
  file "$1" 2>/dev/null | grep -q "RAR archive"
}
export -f verify_rar

function verify_regexp() {
  python3 -c 'import re,sys; p=sys.stdin.read().strip(); try: exit(0 if p and re.compile(p) else 1); except: exit(1)' <"$1" 2>/dev/null
}
export -f verify_regexp

function verify_rss() {
  head -n 1 "$1" 2>/dev/null | grep -q '^<?xml' 2>/dev/null &&
  grep -q -E '<rss version|<feed' "$1" 2>/dev/null
}
export -f verify_rss

function verify_rtf() {
  file "$1" 2>/dev/null | grep -q "Rich Text Format"
}
export -f verify_rtf

function verify_ruby() {
  magika -l "$1" | grep -q ": ruby$" 2>/dev/null
}
export -f verify_ruby

function verify_sfnt() {
  file "$1" 2>/dev/null | grep -q -E "TrueType font|OpenType font|sfnt"
}
export -f verify_sfnt

function verify_sh() {
  magika -l "$1" | grep -q ": shell$" 2>/dev/null
}
export -f verify_sh

function verify_sharedlib() {
  file "$1" 2>/dev/null | grep -q "shared library"
}
export -f verify_sharedlib

function verify_sldworks() {
  file "$1" 2>/dev/null | grep -q "SolidWorks"
}
export -f verify_sldworks

function verify_smtp() {
  head -n 1 "$1" 2>/dev/null | grep -q -E '^HELO |^EHLO |^MAIL FROM:' 2>/dev/null
}
export -f verify_smtp

function verify_snodas() {
  head -c 8 "$1" 2>/dev/null | grep -q "SNODAS"
}
export -f verify_snodas

function verify_speex() {
  file "$1" 2>/dev/null | grep -q "Speex"
}
export -f verify_speex

function verify_sql() {
  magika -l "$1" | grep -q ": sql$" 2>/dev/null
}
export -f verify_sql

function verify_svg() {
  magika -l "$1" | grep -q ": svg$" 2>/dev/null || grep -q '^<svg' "$1" 2>/dev/null
}
export -f verify_svg

function verify_swf() {
  file "$1" 2>/dev/null | grep -q "Macromedia Flash"
}
export -f verify_swf

function verify_tar() {
  file "$1" 2>/dev/null | grep -q "tar archive"
}
export -f verify_tar

function verify_tga() {
  file "$1" 2>/dev/null | grep -q "Targa image"
}
export -f verify_tga

function verify_tiff() {
  file "$1" 2>/dev/null | grep -q "TIFF image"
}
export -f verify_tiff

function verify_tnef() {
  file "$1" 2>/dev/null | grep -q "Transport Neutral Encapsulation Format"
}
export -f verify_tnef

function verify_ttf() {
  file "$1" 2>/dev/null | grep -q "TrueType font"
}
export -f verify_ttf

function verify_unixdump() {
  file "$1" 2>/dev/null | grep -q "Berkeley db.*dump"
}
export -f verify_unixdump

function verify_url() {
  head -n 1 "$1" 2>/dev/null | grep -q -E '^(https?|ftp|file|git|ssh|sftp|ldap)://[^[:space:]]+$' 2>/dev/null
}
export -f verify_url

function verify_vcf() {
  grep -q "BEGIN:VCARD" "$1" && grep -q "END:VCARD" "$1" && grep -q "VERSION:" "$1" 2>/dev/null
}
export -f verify_vcf

function verify_visio() {
  file "$1" 2>/dev/null | grep -q "Microsoft Visio"
}
export -f verify_visio

function verify_wapxhtml() {
  grep -q 'DOCTYPE html PUBLIC "-//WAPFORUM//DTD XHTML Mobile' "$1" 2>/dev/null
}
export -f verify_wapxhtml

function verify_wasm() {
  file "$1" 2>/dev/null | grep -q "WebAssembly"
}
export -f verify_wasm

function verify_wav() {
  file "$1" 2>/dev/null | grep -q "WAVE audio"
}
export -f verify_wav

function verify_wbmp() {
  file "$1" 2>/dev/null | grep -q "WBMP"
}
export -f verify_wbmp

function verify_webdav() {
  grep -q -E '(DAV:|<D:|<d:|xmlns:D=|xmlns:d=)' "$1" &&
  grep -q -E '(<multistatus|<response|<propfind|<allprop|<propstat)' "$1" &&
  grep -q -E '(HTTP/1\.[01]|<resourcetype)' "$1" 2>/dev/null
}
export -f verify_webdav

function verify_webp() {
  file "$1" 2>/dev/null | grep -q "WebP image"
}
export -f verify_webp

function verify_workssheet() {
  file "$1" 2>/dev/null | grep -q "Microsoft Works"
}
export -f verify_workssheet

function verify_x509() {
  openssl x509 -in "$1" -noout >/dev/null 2>&1
}
export -f verify_x509

function verify_xcf() {
  file "$1" 2>/dev/null | grep -q "GIMP XCF image"
}
export -f verify_xcf

function verify_xhtml() {
  head -n 1 "$1" 2>/dev/null | grep -q -i -E '(<!DOCTYPE[^>]*xhtml|<html[^>]*xmlns=|<\?xml[^>]*version=)' 2>/dev/null
}
export -f verify_xhtml

function verify_xlam() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" && echo "$1" | grep -q "\.xlam$"
}
export -f verify_xlam

function verify_xls() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel"
}
export -f verify_xls

function verify_xls2() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" || file "$1" 2>/dev/null | grep -q "Composite Document File V2"
}
export -f verify_xls2

function verify_xls3() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" || file "$1" 2>/dev/null | grep -q "Composite Document File V3"
}
export -f verify_xls3

function verify_xls4() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" || file "$1" 2>/dev/null | grep -q "Composite Document File V4"
}
export -f verify_xls4

function verify_xlsm() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" && echo "$1" | grep -q "\.xlsm$"
}
export -f verify_xlsm

function verify_xlsws3() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" || file "$1" 2>/dev/null | grep -q "Composite Document File V3"
}
export -f verify_xlsws3

function verify_xlsws4() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" || file "$1" 2>/dev/null | grep -q "Composite Document File V4"
}
export -f verify_xlsws4

function verify_xlsx() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel 2007+"
}
export -f verify_xlsx

function verify_xltm() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" && echo "$1" | grep -q "\.xltm$"
}
export -f verify_xltm

function verify_xltx() {
  file "$1" 2>/dev/null | grep -q "Microsoft Excel" && echo "$1" | grep -q "\.xltx$"
}
export -f verify_xltx

function verify_xml() {
  head -n 1 "$1" 2>/dev/null | grep -q '^<?xml' 2>/dev/null
}
export -f verify_xml

function verify_xz() {
  file "$1" 2>/dev/null | grep -q "XZ compressed"
}
export -f verify_xz

function verify_zip() {
  file "$1" 2>/dev/null | grep -q "Zip archive"
}
export -f verify_zip

function verify_zlib() {
  python3 -c "import zlib; zlib.decompress(open('$1', 'rb').read())" >/dev/null 2>&1
}
export -f verify_zlib

function verify_zstd() {
  file "$1" 2>/dev/null | grep -q "Zstandard compressed"
}
export -f verify_zstd

# Find files likely containing the specified format
function find_candidates() {
    # Find files likely containing the specified format
    format="$1"
    find /home/ruaronicola/corpus-fetch-github -type f \( \
      \( \
        -path "*fuzz*" -o -path "*test*" -o -path "*bench*" -o \
        -path "*example*" -o -path "*sample*" -o -path "*corpus*" -o \
        -path "*corpora*" \
      \) \
      -a \( \
        -path "*$format*" \
      \) \
      -a \( \
        -name "*.$format" -o \
        -name "*.bin" -o -name "*.test" -o \
        \( -name "*test*" ! -name "*.*" \) \
      \) \
    \) | sort -u | shuf | head -n 5000
}
export -f find_candidates


file="$1"
format="$2"

if type "verify_$format" &>/dev/null; then
    if "verify_$format" "$file"; then
        exit 0
    else
        echo "Warning: verification failed for $file (does not look like $format)" >&2
        exit 1
    fi
else
    echo "Warning: verification function verify_$format not found" >&2
    exit 1
fi