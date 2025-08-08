FUNCTIONS = [
    {
        "type": "function",
        "function": {
            "name": "finish_task",
            "description": "finish the program analysis task and propose a patch",
            "parameters": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "justify the reasons why you propose the patch and why this patch can fix the vulnerability without harming the functionality",
                    },
                    "patched_functions": {
                        "description": "an array of functions the agent propose to patch",
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "proposed_patch": {
                                    "type": "string",
                                    "description": "the entire patched function source code",
                                },
                                "function_name": {
                                    "type": "string",
                                    "description": "the name of the function in the proposed_patch",
                                },
                            },
                        },
                    },
                    "confidence": {
                        "description": "the confidence on the correctness of the patch",
                        "type": "string",
                        "enum": ["low", "medium", "high", "very high"],
                    },
                },
                "required": ["reasoning", "patched_functions", "confidence"],
            },
        },
    }
]
