## POIGUY

### POI Return Schema

```
json_schema_v2 = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Generated schema for Root",
    "type": "object",
    "properties": {
        "target_id": {
            "type": "string"
        },
        "scanner": {
            "type": "string"
        },
        "detection_strategy": {
            "type": "string"
        },
        "harness_id": {
            "type": "string"
        },
        "crash_reason": {
            "type": "string"
        },
        "pois": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string"
                    },
                    "source_location": {
                        "type": "object",
                        "properties": {
                            "relative_file_path": {
                                "type": "string"
                            },
                            "function_signature": {
                                "type": "string"
                            },
                            "line_text": {
                                "type": "string"
                            },
                            "line_number": {
                                "type": "number"
                            },
                            "symbol_offset": {
                                "type": "number"
                            },
                            "symbol_size": {
                                "type": "number"
                            },
                            "key_index": {
                                "type": "string"
                            }
                        },
                        "required": [
                            "relative_file_path",
                            "function_signature",
                            "line_text",
                            "line_number",
                            "symbol_offset",
                            "symbol_size",
                            "key_index"
                        ]
                    }
                },
                "required": [
                    "reason",
                    "source_location"
                ]
            }
        },
        "stack_traces": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string"
                    },
                    "call_locations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "trace_line": {
                                    "type": "string"
                                },
                                "relative_file_path": {
                                    "type": "string"
                                },
                                "function": {
                                    "type": "string"
                                },
                                "line_text": {
                                    "type": "string"
                                },
                                "line_number": {
                                    "type": "number"
                                },
                                "symbol_offset": {
                                    "type": "number"
                                },
                                "symbol_size": {
                                    "type": "number"
                                },
                                "key_index": {
                                    "type": "string"
                                }
                            },
                            "required": [
                                "trace_line",
                                "relative_file_path",
                                "function",
                                "line_text",
                                "line_number",
                                "symbol_offset",
                                "symbol_size",
                                "key_index"
                            ]
                        }
                    }
                },
                "required": [
                    "reason",
                    "call_locations"
                ]
            }
        },
        "additional_information": {
            "type": "object",
        }
    },
    "required": [
        "target_id",
        "scanner",
        "detection_strategy",
        "harness_id",
        "crash_reason",
        "pois",
    ]
}

```
#### Deprecated
```
json_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$id": "aixcc_poiguy",
    "type": "object",
    "properties": {
        "target_id": {
            "type": "integer"
        },
        "scanner": {
            "type": "string",
            "enum": ["jazzer", "syzkaller"]
        },
        "vulnerability_type": {
            "type": "string",
        },
        "description": {
            "type": "string"
        },
        "detection_strategy": {
            "type": "string",
            "enum": ["fuzzing", "static_analysis"]
        },
        "relative_file_path": {
            "type": "string"
        },
        "function_signature": {
            "type": "string"
        },
        "function": {
            "type": "string"
        },
        'function_start_line': {
            'type': 'integer'
        },
        'function_end_line': {
            'type': 'integer'
        },
        'function_start_column': {
            'type': 'integer'
        },
        'function_end_column': {
            'type': 'integer'
        },
        "crash_line_text": {
            "type": "string"
        },
        "crash_line_number": {
            "type": "integer"
        },
        "additional_information": {
            "type": "object"
        }
    },
    "required": [
        "target_id",
        "scanner",
        "vulnerability_type",
        "description",
        "detection_strategy",
        "relative_file_path",
        "function_signature",
        "function",
        "function_start_line",
        "function_end_line",
        "function_start_column",
        "function_end_column",
        "crash_line_text",
        "crash_line_number",
        "additional_information"
    ]
}
```
