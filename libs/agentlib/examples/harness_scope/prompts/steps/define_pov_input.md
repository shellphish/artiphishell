Based on the code, determine what parts of the POV input map to where that data is used in the harness.

Create a json schema which captures the semantics of how the input is used in the harness. This json schema could be used by a user to easily fill out all parts of the POV input with a higher level of understanding of how the input is used in the harness.

### Schema Format

Use the standard JSON schema format to define the schema. As a reminder of what JSON schema looks like: `{"properties": {"foo": {"title": "Foo", "description": "a list of strings", "type": "array", "items": {"type": "string"}}}, "required": ["foo"]}`. For this example, the object `{"foo": ["bar", "baz"]}` is a well-formatted instance of the schema. The object `{"properties": {"foo": ["bar", "baz"]}}` is not well-formatted.

The top level of the schema should be a json object, where each key represents a specific unique part of the pov input. The name of the key and the provided schema description for the key should be a straightforward name that describes how the value would be used in the harness. This way the user can understand each value they are providing.

Later, once we finish this step, we will create a script to convert an input in this schema back into the original POV byte format. But for now just output the schema.