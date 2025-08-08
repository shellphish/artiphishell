# AFC PoV Deduplication Strategy / Methodology

This directory contains information and scripts to help provide clarity on the pov deduplication
strategy used in AFC Exhibition 3 and the Final Round. This information is written to supplement
the latest P&S Release, but is not a replacement for the rules and scoring in the official guide.

## The Methodology

PoV deduplication is performed pairwise between every permutation of PoVs for a Challenge, and
includes the following steps:

1. A series of pairwise crash-centric comparators are run against each pairing
2. PoVs are tested against all challenge-designed "good patches" to further associate PoVs
3. The results of step 1 and 2 are used to deduplicate PoVs, grouping them into vulnerability bins

After the end of a challenge task, this methodology is used to determine Challenge Vulnerabilities.
A Challenge Vulnerability is defined implicitly by all duplicate PoVs found by all CRSs for that challenge,
plus the competition-designed PoVs prepared for the synthetic vulnerabilities.

### Step 1: Pairwise crash-centric comparators

The crash-centric comparators used in step one have been pulled into these scripts
to provide a reproducible standalone environment to help understand the process.

Instructions on running these scripts is found in the later section of this readme.

### Step 2: Challenge-Designed "good-patch" deduplication

Deduplication should not be focused on the crash-state alone, and as such, step two is focused on
comparing PoVs with the challenge-designed good patches associated with each known vulnerability.

For any known vulnerability, there is a patch designed as a solution to that vulnerability. Because of
this, testing all challenge povs against all designed patches gives us a way to associate povs at
the vulnerability-level, rather than just the crash level.

Specifically, let's consider a challenge with two synthetic vulnerabilities: Vuln A, and Vuln B.

- Let's assume competing CRSs submit a total of 30 PoVs for the challenge task.
- In addition, the challenge will have at least two challenge-provided PoVs (one for each vulnerability).

In this case, step one is performed to analyze all 32 PoVs, and then step two will do the following:

1. Run each PoV against the patched challenge state for both patch A and patch B. This results in
   a set, for each PoV, of which patches solve that PoV.

_Note 1: Step two is independent of step one entirely, and they can be performed independent of each other._

_Note 2: In the case of unknown vulnerability discoveries (0-days, and the like), the game organizers hold
the right to develop "good patches" for the CRS-discovered vulnerabilities, post-round, to be used in this step.
This is ensure fair scoring across both synthetic and non-synthetic CRS discoveries. If and when this is done,
these new good-patch designers will **not** be given access to CRS patch submissions before or during the
development of these patches. They will be designed with challenge PoV information **only**._

### Step 3: Deduplication and Vulnerability Binning

The final step performs the deduplication and challenge vulnerability binning based on the results of
steps one and two. This methodology is as follows:

1. For all PoVs in the challenge, assign each PoV to its own unique vulnerability bin.
2. For all PoV pairs in the challenge, if _any_ comparator in step one considered them
   duplicates, merge the vulnerability bins they are in to a single bin.
3. For all PoV pairs in the challenge, if the intersection of the set of designed patches
   that solve them is non-empty, merge the vulnerability bins they are in to a single bin.

The remaining un-merged vulnerability bins define the Challenge Vulnerabilities for the challenge,
and is the set of Challenge Vulnerabilities used for patch and bundle evaluation and scoring.

## Running these scripts

The scripts in this directory are currently only related to step one of the above process.

### Requirements

These scripts have been tested on Python 3.11, specifically.

### Setting Up

We're assuming a Unix-like for your usage. If you're on Windows, you should be able to replicate the
following command outline pretty easily without breaking a sweat!

1. **From this directory,** clone clusterfuzz.
2. Check out the correct commit for clusterfuzz.
3. Create a new virtual environment, and activate it.
4. Install from `requirements.txt`.

The following should handle this:

```bash
git clone https://github.com/google/clusterfuzz.git \
    && git -C clusterfuzz checkout $(cat clusterfuzz-commit-hash) \
    && python3.11 -m venv venv \
    && . venv/bin/activate \
    && python -m pip install -r requirements.txt
```

You should now be able to run the scripts!

### Directory Overview

`deduplicate_povs.py`: The most important script in the directory! Given an input file with serialized
PoVs ( see its top-level docstring for more information ), it will print a message letting you know whether
or not our system would've determined the input PoVs to be duplicates.

`generate_crash_state.py`: A tool for generating crash states and instrumentation keys for use
by `deuplicate_povs.py`. We'll include a brief explanation of these in this readme, but the docstrings
of the scripts should be helpful as well.

`sample_deduplciation_input.json`: A sample of the kind of structure `deduplicate_povs.py` is expecting
for its input. You can create your own and run it through the script!

`sample_fuzz_output.txt`: A sample fuzzer output that can be used as the input to `generate_crash_state.py`.
You can use your own outputs with that script, too!

`clusterfuzz-commit-hash`: We need clusterfuzz to do deduplication, so we keep the commit that we've got
pinned at the moment in this file.

### Usages

Running deduplication on some input file:

```bash
python3 deduplicate_povs.py -i sample_deduplication_input.json
```

Generating crash states and instrumentation keys from a fuzzer input and writing them to a JSON document:

```bash
python3 generate_crash_state.py -i sample_fuzz_output.txt -o my_file.json
```

### Crash State? Instrumentation Key?

A "Crash State" is a string that's produced by clusterfuzz using a rather large library of heuristics
to determine whether or not two PoVs are duplicates of one-another based on their fuzzer outputs. We
generate these crash states from fuzzer outputs for a part of our deduplication pipeline, and use the
same method that clusterfuzz does.

An "Instrumentation Key", however, is a creation of the AIxCC team. Certain fuzz outputs don't yield
clean crash states, so we devise a key based on the instrumentation signatures found in them when they're
available. The sample fuzz output contained in this repository contains some samples.
