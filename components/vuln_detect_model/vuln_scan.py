import sys
sys.path.append("/app/")

from model_zoo import VllmModel
from model_zoo import LiteLLMModel
from aiolimiter import AsyncLimiter
from utils import  get_cwe_info
import argparse
import asyncio
import os
import json

sys_prompt = "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step."

reasoning = "You should STRICTLY structure your response as follows:"

policy_prefix = "You should only focusing on checking if the code contains the following cwe: "

reasoning_user_prompt = """\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx). \
\n
## You are given the following code snippet:
```
{CODE}
```
\n
{CWE_INFO}
\n
{REASONING}
\n
## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.
{ADDITIONAL_CONSTRAINT}

## Example
- If the code is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A
"""

CWE_IN_SCOPE_SEMI = {"c": [125, 787, 119, 416, 415, 476, 190],
                    "java": [22, 77, 78, 94, 190, 434, 502, 918]}



def scan(args):
    import time

    result_file = "result_all.json"

    if os.path.exists(result_file):
        with open(result_file, "r") as f:
            final_res = json.load(f)
    else:
        final_res = {}

    # Initialize the rate limiter and the LLM model
    limiter = AsyncLimiter(args.requests_per_minute, 60)
    model = LiteLLMModel(
        model="hosted_vllm/" + args.model_name,
        server_url=args.server_url,
        limiter=limiter,
        temperature=args.temperature,
        api_key=args.api_key or None,
    )

    cwe_in_scope = CWE_IN_SCOPE_SEMI[args.language]
    policy = policy_prefix
    for cwe_number in cwe_in_scope:
        cwe_id = f"CWE-{cwe_number}"
        policy += f"\n- {cwe_id}: {get_cwe_info(cwe_number)}"
        assert "Unknown CWE" not in policy, f"Unknown CWE: {cwe_id} is detected"

    name_to_message = {}
    for subdir in ("FUNCTION", "MACRO", "METHOD"):
        dir_path = os.path.join(args.clang_indices, subdir)
        for fname in os.listdir(dir_path):
            if not fname.endswith(".json"):
                continue
            if fname in final_res:
                continue
            file_path = os.path.join(dir_path, fname)
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if len(data["code"]) > 20000:
                print(f"Code snippet too long: {fname}")
                continue
            name_to_message[fname] = [
                {"role": "system", "content": sys_prompt},
                {
                    "role": "user",
                    "content": reasoning_user_prompt.format(
                        CODE=data["code"],
                        CWE_INFO=policy,
                        REASONING=reasoning,
                        ADDITIONAL_CONSTRAINT="",
                    ),
                },
            ]

    all_keys = list(name_to_message.keys())
    messages = list(name_to_message.values())

    BATCH_SIZE = 1000
    for i in range(0, len(messages), BATCH_SIZE):
        print(f"Processing batch {i} ~ {i + BATCH_SIZE - 1}")
        batch_messages = messages[i:i + BATCH_SIZE]
        batch_keys = all_keys[i:i + BATCH_SIZE]

        try:
            resps, latencies = asyncio.run(
                model.batch_chat_completion(
                    batch_messages,
                    temperature=args.temperature,
                    max_tokens=8192,
                )
            )
        except Exception as e:
            print(f"Batch failed: {e}")
            continue

        for idx, key in enumerate(batch_keys):
            try:
                final_res[key] = {
                    "req": name_to_message[key][1]["content"],
                    "res": resps[idx].choices[0].message.content,
                }
            except Exception as e:
                print(f"Failed to save result for {key}: {e}")

        with open(result_file, "w") as f:
            json.dump(final_res, f, indent=2)

        print(f"[+] Batch {i} ~ {i + BATCH_SIZE - 1} saved to {result_file}")

    return final_res





if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument(
        "--clang_indices",
        type=str,
        required=True,
        help="The path to the clang indices folder, which contains three folders: FUNCTION, MACRO, and METHOD."
    )
    parser.add_argument(
        "--language",
        type=str,
        required=True,
        choices=["c", "c++", "java", "jvm"],
        help="The programming language of the code snippets."
    )
    parser.add_argument(
        "--requests_per_minute",
        type=int,
        default=180,
        help="The maximum number of requests per minute."
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.5,
        help="The temperature for the model's responses."
    )
    parser.add_argument(
        "--server_url",
        type=str,
        default="http://localhost:25001/v1",
        help="The URL of the model server."
    )
    parser.add_argument(
        "--model_name",
        type=str,
        default="secmlr/DS-Noisy_DS-Clean_QWQ-Noisy_QWQ-Clean_Qwen2.5-7B-Instruct_full_sft_1e-5",
        help="The name of the model to use."
    )
    parser.add_argument(
        "--api_key",
        type=str,
        default="",
        help="The API key for the model server."
    )
    args = parser.parse_args()
    if args.language == "jvm":
        args.language = "java"
    if args.language == "c++":
        args.language = "c"
    scan(args)

# python vuln_scan.py --server_url http://127.0.0.1:25002/v1 --clang_indices /aixcc-backups/backup-full-nginx-11889160244/clang_index.output_dir/nginx --language c