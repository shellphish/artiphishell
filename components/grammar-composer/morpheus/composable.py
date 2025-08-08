import base64
import filetype
import hashlib
import magic
# import magika
import re

from collections import defaultdict

from morpheus.config import REFERENCE_GRAMMARS_FILEPATHS
from morpheus.magic import MIME_TO_NAME
from morpheus.utils import token_quality, exception_wrapper, log


class Composition:
    def __init__(self, internal_rule_hash, internal_parent_hash, external_grammar, external_rule=None, external_nonterm=None, encoding=None):
        self.internal_rule_hash = internal_rule_hash
        self.internal_parent_hash = internal_parent_hash
        # NOTE: grammar is nullable and should be none to "just insert a rule"
        self.external_grammar = external_grammar
        self.external_rule = external_rule
        self.external_nonterm = external_nonterm
        self.encoding = encoding

        self.hexdigest = hashlib.sha256(
            f"{self.internal_rule_hash}:{self.internal_parent_hash}:{self.external_grammar.hexdigest}:{self.external_rule or ''}:{self.external_nonterm or ''}:{self.encoding or ''}".encode('utf-8')
        ).hexdigest()

    def __repr__(self):
        return f"Composition({self.hexdigest}, {self.internal_rule_hash=}, {self.internal_parent_hash=}, {self.external_grammar.name=}, {self.external_rule=}, {self.external_nonterm=}, {self.encoding=})"
    
    # compare everything except the id
    def __hash__(self):
        return hash(self.hexdigest)
    
    def __eq__(self, other):
        if not isinstance(other, Composition):
            return False
        return self.hexdigest == other.hexdigest

class Composable:
    MAGIC = magic.Magic(mime=True)
    # MAGIKA = magika.Magika()

    XML_START_REGEX = re.compile(b"<([a-zA-Z][a-zA-Z0-9:-]{0,61})>", re.DOTALL)
    BASE64_VALID_BYTES = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
    @staticmethod
    def IS_MAYBE_XML(data):
        start_match = Composable.XML_START_REGEX.match(data[:64])
        return start_match and data.endswith(b"</" + start_match.group(1) + b">")
    @staticmethod
    def IS_MAYBE_BASE64(data):
        if data and (len(data) % 4 == 0):
            end_sample = data[-64:] if len(data) > 64 else data
            start_sample = data[:64] if len(data) > 128 else data[:len(data)-len(end_sample)] if len(data) > len(end_sample) else b""
            if (
                all(c in Composable.BASE64_VALID_BYTES for c in end_sample[:-2]) and 
                all(c in Composable.BASE64_VALID_BYTES for c in start_sample) and
                all(c in Composable.BASE64_VALID_BYTES | {ord(b'=')} for c in end_sample[-2:])
            ):
                return True

    @staticmethod
    @exception_wrapper()
    def _magic_guess_one(seed, token_quality_threshold=0.5):
        prefix = seed[:4]
        suffix = seed[-4:]
        # discard low quality prefixes
        if token_quality(prefix) < token_quality_threshold:
            return None

        mime = Composable.MAGIC.from_buffer(seed)
        if mime is None or mime not in MIME_TO_NAME:
            mime = filetype.guess(seed)
            mime = mime.mime if mime else None

        if mime is None and Composable.IS_MAYBE_XML(seed):
            mime = "text/xml"

        return mime

    @staticmethod
    @exception_wrapper()
    def magic_guess_one(seed, token_quality_threshold=0.5):
        mime = Composable._magic_guess_one(seed, token_quality_threshold)
        if mime is not None:
            return mime, None
        
        if Composable.IS_MAYBE_BASE64(seed):
            try:
                seed_decoded = base64.b64decode(seed)
            except:
                return None, None
            else:
                mime = Composable._magic_guess_one(seed_decoded, token_quality_threshold)
                if mime is not None:
                    return mime, "base64"
                    
        return None, None

    @staticmethod
    @exception_wrapper()
    def magic_similarity(seeds, threshold=1.0, token_quality_threshold=0.5):
        # discard low quality prefixes
        prefixes = {seed[:4] for seed in seeds if seed and len(seed) >= 4}
        high_quality_prefixes = {prefix for prefix in prefixes if token_quality(prefix) > token_quality_threshold}
        if not high_quality_prefixes:
            return

        MAX_MISSED_MATCHES = (1 - threshold) * len(seeds)

        # NOTE: filetype takes ~5us per seed, magic takes ~50us per seed
        match_counts = defaultdict(int)
        for seed in seeds:
            kind = Composable.MAGIC.from_buffer(seed)
            # NOTE: libmagic is generally more accurate, but sometimes misses (e.g., PNG in grammar-guy-tika)
            if kind is None or kind not in MIME_TO_NAME:
                kind = filetype.guess(seed)
                kind = kind.mime if kind else None
            match_counts[kind] += 1
            # break early if we cannot meet the threshold
            if match_counts.get(None, 0) > MAX_MISSED_MATCHES:
                match_counts.clear()
                break
        match_counts.pop(None, None)

        # try xml regex if we don't have any matches
        # NOTE: magic and filetype do not detect xml without header
        if seeds and not match_counts:
            seed_iter = iter(seeds)
            seed = next(seed_iter)
            if Composable.IS_MAYBE_XML(seed):
                kind = "text/xml"
                for seed in seed_iter:
                    if not Composable.IS_MAYBE_XML(seed):
                        break
                else:
                    match_counts[kind] += len(seeds)

        # try magika if we don't have any matches
        # NOTE: magika is quite slow (5ms per seed)
        # if seeds and not match_counts:
        #     seed_iter = iter(seeds)
        #     kind = MAGIKA.identify_bytes(next(seed_iter)).output.mime_type
        #     if kind in MIME_TO_NAME:
        #         for seed in itertools.islice(seed_iter, 10):
        #             _kind = MAGIKA.identify_bytes(seed).output.mime_type
        #             if _kind != kind:
        #                 log.debug(f"[Magika] Breaking out with {_kind}")
        #                 break
        #         else:
        #             # if we get enough consistent matches from magika, let's call this a match
        #             log.debug(f"[Magika] Detected {kind}")
        #             match_counts[kind] += len(seeds)

        for mime, count in match_counts.items():
            confidence = count / len(seeds)
            if confidence >= threshold and mime in MIME_TO_NAME:
                mime_name = MIME_TO_NAME[mime]
                reference_grammar_nt = "START"
                for reference_grammar_name in REFERENCE_GRAMMARS_FILEPATHS:
                    if reference_grammar_name == mime_name or reference_grammar_name.startswith(f"{mime_name}@"):
                        yield reference_grammar_name, reference_grammar_nt, confidence
