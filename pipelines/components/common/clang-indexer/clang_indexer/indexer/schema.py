output_schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Generated schema for Root",
    "type": "object",
    "properties": {
        "hash": {
            "type": "string"
        },
        "code": {
            "type": "string"
        },
        "signature": {
            "type": ["string", "null"]
        },
        "start_line": {
            "type": "number"
        },
        "start_column": {
            "type": "number"
        },
        "start_offset": {
            "type": "number"
        },
        "end_line": {
            "type": "number"
        },
        "end_column": {
            "type": "number"
        },
        "end_offset": {
            "type": "number"
        },
        "global_variables": {
            "type": "array",
            "items": {}
        },
        "func_return_type": {
            "type": "string"
        },
        "arguments": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "local_variables": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "class_name": {
            "type": "string"
        },
        "funcname": {
            "type": "string"
        },
        "func_calls_in_func_with_fullname": {
            "type": "array",
            "items": {}
        },
        "java": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string"
                }
            },
            "required": [
            ]
        },
        "filepath": {
            "type": "string"
        },
        "filename": {
            "type": "string"
        },
        "comments": {
            "type": "array",
            "items": {}
        },
        "cfg": {
            "type": "string"
        }
    },
    "required": [
        "hash",
        "code",
        "signature",
        "start_line",
        "start_column",
        "start_offset",
        "end_line",
        "end_column",
        "end_offset",
        "global_variables",
        "func_return_type",
        "arguments",
        "local_variables",
        "funcname",
        "func_calls_in_func_with_fullname",
        "filepath",
        "filename"
    ]
}
