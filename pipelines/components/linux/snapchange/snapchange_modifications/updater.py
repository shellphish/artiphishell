# python3 /jazzer_modifications/harness_updater/updater.py --target_harness "$PWD/$HARNESS_FILE" --modified_target_harness "$PWD/$HARNESS_FILE" --srcdir "$PWD" --tmpdir "$TEMP_DIR"
import litellm
import os
import argparse

# take input file and output file as arguments
parser = argparse.ArgumentParser()
parser.add_argument("--input-file", type=str, required=True, help="Path to the input file")
parser.add_argument("--output-file", type=str, required=True, help="Path to the output file")
args = parser.parse_args()

# setting up the API key
os.environ["OPENAI_API_KEY"] = "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"

# prompt template
print("Reading source code from file")
with open(args.input_file, "r") as f:
    source_code = f.read()

injection_code = "take_snapshot(blob);"

system_prompt = """You will be given with a task of injecting a function in the given code based on some requirments.\n\nHere is the code, #Code:\n{}\n\nHere is the function invocation that you are supposed to inject #Function:\n{}\n#Instructions:\n1. In the given code, you have to first identify the a line that takes input from user.\n2. You then need to inject #FUNCTION after the input line, such that the buffer used in the input line is given as argument to the parameter.\n3.Do not create function declaration for #Function, only add the invocation\n4. Do not write any conversational response, and only provide the entire code back (including all the functions) that was given to you by #Code with the modifications""".format(source_code, injection_code)
#system_prompt = "Give me a poem as Captain Jack Sparrow"
# create a completion
messages = [{ "content": system_prompt,"role": "user"}]

print("Sending request to API")
print("message: {}".format(messages))
response = litellm.completion(messages=messages, model="gpt-4-turbo")

print("---------\n\n\nResponse:---------\n{}".format(response["choices"][0]["message"]["content"]))

print("Writing output to file")
with open(args.output_file, "w") as f:
    f.write(str(response["choices"][0]["message"]["content"]))


