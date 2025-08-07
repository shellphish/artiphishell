Read the generated POV input json schema from the previous step.
You now need to create a python3 function which will convert an instance of that user input json struct back into the original POV byte format which the original Harness expects.

Pay close attention to the type of each value in the json schema. You will have to do the correct byte encoding for each type.

Here is a prototype for the function you need to implement:
```python
def convert_to_harness_input(structure: dict) -> bytes:
    # Convert the structure back into the format the harness expects
```