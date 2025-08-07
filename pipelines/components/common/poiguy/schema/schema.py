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
        "fuzzer": {
            "type": "string",
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
        "fuzzer",
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
        "fuzzer": {
            "type": "string",
        },
        "harness_info_id": {
            "type": "string"
        },
        "harness_id": {
            "type": "string"
        },
        "crash_id": {
            "type": "string"
        },
        "crash_report_id": {
            "type": "string"
        },
        "cp_harness_id": {
            "type": "string"
        },
        "cp_harness_name": {
            "type": "string"
        },
        "cp_harness_source_path": {
            "type": "string"
        },
        "cp_harness_binary_path": {
            "type": "string"
        },
        "consistent_sanitizers": {
            "type": ["array", "null"],
            "items": {
                "type": "string"
            }
        },
        "inconsistent_sanitizers": {
            "type": ["array", "null"],
            "items": {
                "type": "string"
            }
        },
        "sanitizer_history": {
            "type": ["array", "null"],
            "items": {
                "type": ["array"],
                "items": {
                    "type": ["string"]
                }
            }
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
                        "type": ["string", "null"]
                    },
                    "source_location": {
                        "type": "object",
                        "properties": {
                            "relative_file_path": {
                                "type": ["string", "null"]
                            },
                            "function_signature": {
                                "type": ["string", "null"]
                            },
                            "line_text": {
                                "type": ["string", "null"]
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
                                "type": ["string", "null"]
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
                        "type": ["string", "null"]
                    },
                    "call_locations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "trace_line": {
                                    "type": ["string", "null"]
                                },
                                "relative_file_path": {
                                    "type": ["string", "null"]
                                },
                                "function": {
                                    "type": ["string", "null"]
                                },
                                "function_name": {
                                    "type": ["string", "null"]
                                },
                                "line_text": {
                                    "type": ["string", "null"]
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
                                    "type": ["string", "null"]
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
    "additionalProperties": False,
    "required": [
        "target_id",
        "scanner",
        "detection_strategy",
        "fuzzer",
        "harness_info_id",
        "cp_harness_id",
        "cp_harness_name",
        "cp_harness_source_path",
        "cp_harness_binary_path",
        "consistent_sanitizers",
        "harness_id",
        "crash_reason",
        "pois",
    ]
}
