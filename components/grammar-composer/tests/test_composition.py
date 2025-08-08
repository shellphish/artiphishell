import pytest
from morpheus.grammar import Grammar


class TestComposition:
    
    def verify_composition(self, grammar_str, wanted_matches, confidence_threshold=1.0):
        grammar = Grammar.from_string(grammar_str)
        assert grammar is not None, "Failed to parse grammar"
        seeds_sample = set(grammar.seed_iterator(nt="START", n=10))
        assert len(seeds_sample) >= 1, f"Failed to generate seeds. Expected >= 1, got {len(seeds_sample)}"

        splicing_candidates = set()
        for configuration in grammar.iter_composition_replacements(max_samples=10, confidence_threshold=confidence_threshold):
            for candidate in configuration:
                splicing_candidates.add(candidate)
        assert len(splicing_candidates) >= len(wanted_matches), \
            f"Failed to find splicing candidates. Expected >= {len(wanted_matches)}, got {len(splicing_candidates)}"
        
        # all splicing must be for one of the wanted matches
        for internal_rule, external_grammar_name, external_grammar_nt, encoding in splicing_candidates:
            for internal_nt, fileformat, confidence in wanted_matches:
                if internal_rule.nt == internal_nt:
                    assert external_grammar_name.startswith(fileformat)
                    # assert splicing_confidence >= confidence, \
                    #     f"Failed to find splicing confidence. Expected >= {confidence}, got {splicing_confidence}"
                    break
            else:
                # assert splicing_confidence < confidence, \
                #     f"Missing wanted match for splicing candidate {internal_rule.nt} -> {external_grammar_name}"
                pass
        
        # all wanted matches must have at least one splicing candidate
        for internal_nt, fileformat, confidence in wanted_matches:
            for internal_rule, external_grammar_name, external_grammar_nt, encoding in splicing_candidates:
                if internal_rule.nt == internal_nt:
                    assert external_grammar_name.startswith(fileformat)
                    # assert splicing_confidence >= confidence, \
                    #     f"Failed to find splicing confidence. Expected >= {confidence}, got {splicing_confidence}"
                    break
            else:
                assert False, f"Missing splicing candidate for wanted match {internal_nt} -> {fileformat}"

        composition_iter = grammar.iter_compositions(confidence_threshold=confidence_threshold)
        new_grammars = list(composition_iter)
        
        # NOTE: could have multiple splicing candidates but only one composition (e.g., PDF + PDF@CORPUS)
        MIN_COMPOSITIONS = 1 if len(wanted_matches) > 0 else 0
        MAX_COMPOSITIONS = float("inf") if len(wanted_matches) > 0 else 0
        assert len(new_grammars) >= MIN_COMPOSITIONS, \
            f"Failed to generate compositions. Expected >= {MIN_COMPOSITIONS}, got {len(new_grammars)}"
        assert len(new_grammars) <= MAX_COMPOSITIONS, \
            f"Failed to generate compositions. Expected <= {MAX_COMPOSITIONS}, got {len(new_grammars)}"
        
        # all compositions must be for one of the wanted matches
        for new_grammar in new_grammars:
            non_encoded_internal_nt = f"artiphishell_non_encoded_{fileformat}".upper()
            assert any(
                # NOTE: there an intermediate rule for encoded imports
                f"ctx.external('{internal_nt}', '{fileformat}" in new_grammar.serialize() or f"ctx.external('{non_encoded_internal_nt}" in new_grammar.serialize()
                for internal_nt, fileformat, confidence in wanted_matches
            ), "Unexpected composition"+new_grammar.serialize()
            
        # all wanted matches must have at least one composition
        for internal_nt, fileformat, confidence in wanted_matches:
            non_encoded_internal_nt = f"artiphishell_non_encoded_{fileformat}".upper()
            assert any(
                # NOTE: there an intermediate rule for encoded imports
                f"ctx.external('{internal_nt}', '{fileformat}" in new_grammar.serialize() or f"ctx.external('{non_encoded_internal_nt}" in new_grammar.serialize()
                for new_grammar in new_grammars
            ), f"Missing composition for wanted match {internal_nt} -> {fileformat}"

    def test_composition_binary_pdf(self):
        grammar_str = """
ctx.rule("START", "{BINARY_FILE}")
ctx.rule("BINARY_FILE", "{PDF_FILE}")
ctx.rule("PDF_FILE", "%PDF-1.{PDF_VERSION}\\n{PDF_CONTENT}%%EOF")
ctx.regex("PDF_VERSION", "[0-7]")
ctx.regex("PDF_CONTENT", "[ -~\\n]*")
"""
        self.verify_composition(grammar_str, [("PDF_FILE", "PDF", 1.0)])

    def test_composition_binary_hardcoded_pdf(self):
        grammar_str = """
ctx.rule("START", "{BINARY_FILE}")
ctx.rule("BINARY_FILE", "{PDF_FILE}")
ctx.rule("PDF_FILE", "%PDF-1.4\\nThis is a PDF file%%EOF")
"""
        self.verify_composition(grammar_str, [("PDF_FILE", "PDF", 1.0)])

    def test_composition_text_xml(self):
        grammar_str = """
ctx.rule("START", "{TEXT_FILE}")
ctx.rule("TEXT_FILE", "{XML_FILE}")
ctx.rule("XML_FILE", "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n")
"""
        self.verify_composition(grammar_str, [("XML_FILE", "XML", 1.0)])

    def test_composition_text_xml_without_header(self):
        grammar_str = """
ctx.rule("START", "{TEXT_FILE}")
ctx.rule("TEXT_FILE", "{XML_FILE}")
ctx.script("XML_FILE", ["TAG", "XML_CONTENT"], lambda TAG, XML_CONTENT: b"<" + TAG + b">" + XML_CONTENT + b"</" + TAG + b">")
ctx.rule("XML_CONTENT", "{XML_ELEMENT}{XML_CONTENT}")
ctx.rule("XML_CONTENT", "")
ctx.script("XML_ELEMENT", ["TAG", "XML_ATTRS", "TEXT_CONTENT"], lambda TAG, XML_ATTRS, TEXT_CONTENT: b"<" + TAG + b" " + XML_ATTRS + b">" + TEXT_CONTENT + b"</" + TAG + b">")
ctx.rule("XML_ELEMENT", "<{TAG}{XML_ATTRS}/>")
ctx.rule("XML_ATTRS", " {XML_ATTR}{XML_ATTRS}")
ctx.rule("XML_ATTRS", "")
ctx.rule("XML_ATTR", "{ATTR_NAME}=\\"{ATTR_VALUE}\\"")
ctx.regex("TAG", "[a-z][a-z0-9]{1,10}")
ctx.regex("ATTR_NAME", "[a-z][a-z0-9]{1,10}")
ctx.regex("ATTR_VALUE", "[a-zA-Z0-9]{1,20}")
ctx.regex("TEXT_CONTENT", "[a-zA-Z0-9]{1,20}")
"""
        self.verify_composition(grammar_str, [("XML_FILE", "XML", 1.0)])

    def test_composition_text_json(self):
        grammar_str = """
ctx.rule("START", "{TEXT_FILE}")
ctx.rule("TEXT_FILE", "{JSON_FILE}")
ctx.rule("JSON_FILE", "{OPEN_BRACKET}{JSON_CONTENT}{CLOSE_BRACKET}")
ctx.rule("JSON_CONTENT", "{JSON_PAIR},{JSON_CONTENT}")
ctx.rule("JSON_CONTENT", "{JSON_PAIR}")
ctx.rule("JSON_PAIR", "{STRING}:{VALUE}")
ctx.rule("STRING", "{QUOTED_STRING}")
ctx.rule("VALUE", "{QUOTED_STRING}")
ctx.rule("VALUE", "{NUMBER}")
ctx.regex("QUOTED_STRING", "\\"[a-zA-Z0-9 ,.!?]{1,20}\\"")
ctx.regex("NUMBER", "[0-9]+")
ctx.literal("OPEN_BRACKET", "{")
ctx.literal("CLOSE_BRACKET", "}")
"""
        self.verify_composition(grammar_str, [("JSON_FILE", "JSON", 1.0)])

    def test_composition_text_html(self):
        grammar_str = """
ctx.rule("START", "{HTML_FILE}")
ctx.rule("HTML_FILE", "<!DOCTYPE html><html>{HTML_CONTENT}</html>")
ctx.rule("HTML_CONTENT", "{HTML_ELEMENT}{HTML_CONTENT}")
ctx.rule("HTML_CONTENT", "")
ctx.script("HTML_ELEMENT", ["TAG", "HTML_ATTRS", "HTML_CONTENT"], lambda TAG, HTML_ATTRS, HTML_CONTENT: b"<" + TAG + b" " + HTML_ATTRS + b">" + HTML_CONTENT + b"</" + TAG + b">")
ctx.rule("HTML_ELEMENT", "<{TAG}{HTML_ATTRS}/>")
ctx.rule("HTML_ATTRS", " {HTML_ATTR}{HTML_ATTRS}")
ctx.rule("HTML_ATTRS", "")
ctx.rule("HTML_ATTR", "{ATTR_NAME}=\\"{ATTR_VALUE}\\"")
ctx.regex("TAG", "[a-z][a-z0-9]{1,10}")
ctx.regex("ATTR_NAME", "[a-z][a-z0-9]{1,10}")
ctx.regex("ATTR_VALUE", "[a-zA-Z0-9 ,.!?]{1,20}")
"""
        self.verify_composition(grammar_str, [("HTML_FILE", "HTML", 1.0)])

    def test_composition_hardcoded_overlapping_rules(self):
        grammar_str = """
ctx.rule("START", "{PDF_FILE}")
ctx.rule("START", "{ZIP_FILE}")
ctx.rule("START", "{XML_FILE}")
ctx.rule("START", "{HTML_FILE}")
ctx.literal("PDF_FILE", b"%PDF-1.4\\n1 0 obj\\n<</Type/Catalog/Pages 2 0 R>>\\nendobj\\n2 0 obj\\n<</Type/Pages/Kids[3 0 R]/Count 1>>\\nendobj\\n3 0 obj\\n<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>\\nendobj\\nxref\\n0 4\\n0000000000 65535 f\\n0000000009 00000 n\\n0000000058 00000 n\\n0000000111 00000 n\\ntrailer\\n<</Size 4/Root 1 0 R>>\\nstartxref\\n178\\n%%EOF\\n")
ctx.literal("ZIP_FILE", b"PK\\x03\\x04\\x14\\x00\\x00\\x00\\x08\\x00\\x00\\x00!\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00test.txt\\x00\\x00\\x00PK\\x01\\x02\\x14\\x00\\x14\\x00\\x00\\x00\\x08\\x00\\x00\\x00!\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00test.txtPK\\x05\\x06\\x00\\x00\\x00\\x00\\x01\\x00\\x01\\x00.\\x00\\x00\\x00\\x1c\\x00\\x00\\x00\\x00\\x00")
ctx.literal("XML_FILE", b"<?xml version='1.0' encoding='UTF-8'?>\\n<root><content>Test content</content></root>")
ctx.literal("HTML_FILE", b"<!DOCTYPE html><html><head><title>Test</title></head><body><p>Test content</p></body></html>")
"""
        self.verify_composition(grammar_str, [
            ("PDF_FILE", "PDF", 1.0), 
            ("ZIP_FILE", "ZIP", 1.0), 
            ("XML_FILE", "XML", 1.0), 
            ("HTML_FILE", "HTML", 1.0)
        ])

    def test_composition_low_quality_token_ico(self):
        grammar_str = """
ctx.rule("START", "{ICO_FILE}")
ctx.literal("ICO_FILE", b"\\x00\\x00\\x01\\x00")
"""
        self.verify_composition(grammar_str, [])

    def test_composition_nested_xml(self):
        grammar_str = """
ctx.rule("START", "{XML_FILE}")
ctx.rule("XML_FILE", "<root>{XML_CONTENT}</root>")
ctx.rule("XML_CONTENT", "{XML_ELEMENT}{XML_CONTENT}")
ctx.rule("XML_CONTENT", "")
ctx.script("XML_ELEMENT", ["TAG", "XML_CONTENT"], lambda TAG, XML_CONTENT: b"<" + TAG + b">" + XML_CONTENT + b"</" + TAG + b">")
ctx.regex("TAG", "[a-z][a-z0-9]{1,10}")
"""
        self.verify_composition(grammar_str, [("XML_FILE", "XML", 1.0), ("XML_ELEMENT", "XML", 1.0)])

    def test_composition_splice_confidence(self):
        grammar_str = """
ctx.rule("START", "{HTML_FILE}")
ctx.rule("HTML_FILE", "{PREFIX}<a>{TEXT_CONTENT}</a>")
ctx.rule("HTML_FILE", "{BAD_PREFIX}<a>{TEXT_CONTENT}</a>")
ctx.rule("BAD_PREFIX", "<prefix>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.rule("PREFIX", "<!DOCTYPE html>")
ctx.regex("TEXT_CONTENT", "[a-zA-Z0-9]{1,20}")
"""
        self.verify_composition(grammar_str, [("HTML_FILE", "HTML", 0.5), ("PREFIX", "HTML", 0.5)], confidence_threshold=0.5)

    def test_composition_base64_encoding(self):
        grammar_str ="""
ctx.rule("START", "{BASE64_DATA}")
ctx.rule("BASE64_DATA", "{BASE64_DATA_TXT}")
ctx.rule("BASE64_DATA", "{BASE64_DATA_HTML}")
ctx.rule("BASE64_DATA", "{BASE64_DATA_PNG}")
ctx.rule("BASE64_DATA_TXT", b"SGVsbG8gV29ybGQ=")
ctx.rule("BASE64_DATA_HTML", b"PGh0bWw+PGJvZHk+SGVsbG8hPC9ib2R5PjwvaHRtbD4=")
ctx.rule("BASE64_DATA_PNG", b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
        """
        self.verify_composition(grammar_str, [("BASE64_DATA_PNG", "PNG", 1.0), ("BASE64_DATA_HTML", "HTML", 1.0)])