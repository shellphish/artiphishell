FUNCTIONS = [
    {
        "type": "function",
        "function": {
            "name": "propose_plan",
            "description": "propose a plan to patch the vulnerability in the function",
            "parameters": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "justify the reasons why you propose the patch and why this patch can fix the vulnerability without harming the functionality",
                    },
                    "side_effect": {
                        "type": "string",
                        "description": "the possible side effects of the patch",
                    },
                    "proposed_plan": {
                        "type": "string",
                        "description": "a plan to patch the vulnerability in the function",
                    },
                    "variable_use": {
                        "type": "string",
                        "description": "list all variables, macros, classes and other elements that you will use in the patch, separated with spaces.",
                    },
                    "confidence": {
                        "description": "the confidence on the correctness of the patch",
                        "type": "string",
                        "enum": ["low", "medium", "high", "very high"],
                    },
                },
                "required": ["reasoning", "side_effect", "proposed_plan", "variable_use", "confidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refine_plan",
            "description": "refine the plan to patch the vulnerability in the function",
            "parameters": {
                "type": "object",
                "properties": {
                    "refined_plan": {
                        "type": "string",
                        "description": "a refined plan to patch the vulnerability in the function",
                    }
                },
                "required": ["refined_plan"],
            },
        },
    },
]
