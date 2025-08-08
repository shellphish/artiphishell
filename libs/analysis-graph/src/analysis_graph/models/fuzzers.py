KNOWN_FUZZER_NAMES = [
    # UNSET
    '',

    # the baseline OSS-Fuzz ones 
    'afl',
    'libfuzzer',
    'honggfuzz',
    'centipede',

    'shellphish_aflpp',
    'grammar-guy',
    'quickseed',
    'discovery-guy'
]
KNOWN_FUZZER_NAMES_PROPERTY_CHOICES = {
    n: n for n in KNOWN_FUZZER_NAMES
}