# cJSON
- cJSON is a lightweight C library for parsing and generating JSON (JavaScript Object Notation).

## Source files

The cJSON library typically includes the following source files:

- cJSON.c: The main implementation file containing core functions for parsing, printing, and managing JSON data.
- cJSON.h: The header file declaring the functions, structures, and constants used in the library.
- cJSON_Utils.c: Additional utility functions for working with JSON, such as merging, comparing, and searching JSON objects.
- cJSON_Utils.h: The header file for the utility functions.

## Main functions 

### Parsing JSON:
  - cJSON_Parse(const char *value): Parses a JSON string and returns a cJSON object.
  - cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON_bool require_null_terminated): Parses a JSON string with options.

### Generating JSON:
- cJSON_Print(const cJSON *item): Returns a formatted JSON string.
- cJSON_PrintUnformatted(const cJSON *item): Returns an unformatted JSON string.
- cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt): Prints JSON to a buffer with a pre-allocated size.

### Memory Management:
- cJSON_InitHooks(cJSON_Hooks* hooks): Initializes custom memory allocation hooks.

### Utility Functions:
- cJSON_Compare(const cJSON *a, const cJSON *b, cJSON_bool case_sensitive): Compares two cJSON objects.
- cJSON_Utils_MergePatch(cJSON *target, const cJSON *patch): Applies a JSON Merge Patch.

## Inputs

- String Input: JSON data is provided as a null-terminated string for parsing functions.
- Configuration Flags: Some functions accept flags or options, such as requiring null-terminated strings or choosing formatted output.