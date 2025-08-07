

Q: can we detect the difference of high-quality human inputs vs. low-quality fuzzer-generated inputs?

I:
    -   high complexity correlation (human inputs exercise a lot of functionality together as opposed to input-minimizing fuzzers)

Q: Can we collect a global corpus of all files and file formats we've ever seen?
    - How can we use them to kickstart dynamic analysis most effectively
    - How can we adapt inputs for slightly modified formats/protocools (e.g. needing a prefix before parsing the file format)
    - How can we use them to inform better mutations?

Q: Can we use the global corpus to fingerprint possible functionality in the program?
    - E.g. if zip files lead to better coverage => maybe harness zip logic for fuzzing

