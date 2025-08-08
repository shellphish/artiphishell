# AIJON Lib

This library is supposed to be used by the AIJON task (as well as others) for the purpose of annotating C/C++ programs with IJON style annotations for fuzzing using LLMs.

Currently, AIJON Lib can be used to annotate code based on points-of-interest (POIs) which can be any of:
1. Codeswipe rankings
2. Code diffs
3. Sarif reports (TODO)


# How to use AIJON ?

Since AIJON annotates code using LLMs, it is not practical to annotate large code bases like nginx.

The better way to use AIJON is for smaller scopes. For example, a few functions.

For this purpose, AIJON requires a Point-of-Interest (POI) that is used to direct the LLM annotations.
These POIs are typically locations where you'd want the fuzzer to concentrate.

## Generating POI objects

A POI in AIJON is essentially a dictionary containing the following keys:
```python
{
    "function_index_key": "FOO", # The function index key used to look up functions in the function resolver
    # All other fields are optional and can be modified to provide additional info regarding the POI to the LLM.
}
```

You can create these POIs in the following manner:

```python
from aijon_lib import PatchPOI, CodeSwipePOI, SarifPOI

# The path to your POI goes here.
# Can be a patch file or a codeswipe rankings yaml file
POI_REPORT_PATH = ""

poi_obj = PatchPOI(
    full_function_indices_path=full_function_indices,
    target_functions_json_dir=target_functions_json_dir
    )

poi_obj.add_report(POI_REPORT_PATH)
```

A POI object can store multiple POI's (multiple patch locations, multiple codeswipe locations etc)
You can iterate over all POI's within the object.

```python
for poi in poi_obj.get_next_poi():
    # Do something with poi
    pass

# You can also just get a list of all POI's
all_pois = poi_obj.get_all_pois()
```

## Instrumenting code with AIJON

Once we have a POI object, AIJON Lib provides a function `instrument_code_with_ijon` which queries the LLM for annotations.

```python
cost, llm_response = instrument_code_with_ijon(
    poi, # A single POI from the POI object
    function_index, # The FunctionIndex object you get from the function resolver
    source_code_dir, # A Path object to the location where the code exists
    retry_limit=3, # If the LLM makes a mistake, we retry it for these many iterations
    write_out=True, # If you want the annotated code to be written in the source_code_dir
)
```

And that's it, you have your fancy annotated code now.


# Notes
1. If `write_out` is set to True in `instrument_code_with_ijon`, it will modify the contents of `source_code_dir`. Make a backup of the source code unless you know what you're doing.

2. CodeSwipe POI's are filtered with a priority_score threshold of 5.0 (or the top 10 highest scoring POI's)

3. Diff POI's are filtered down to 100 functions changed.

4. Sarif POI's aren't supported yet 🙂.