extern crate pyo3;
extern crate rand;

pub mod afl;
pub mod jazzer;

use rand::Rng;

use fuzzer::python_grammar_loader;
use crate::afl::CustomMutator;
use crate::jazzer::CustomJazzerMutator;

use grammartec::context::Context;
use grammartec::mutator::Mutator;
use grammartec::seed_serialization::SerializedSeed;
use grammartec::tree::TreeLike;
use ron::ser::PrettyConfig;
use std::collections::HashMap;

// Mutator implementations

pub fn get_context_for_input(map: &mut HashMap<String, Context>, input: &SerializedSeed) -> Context {
    if !map.contains_key(&input.grammar_hash) {
        let mut ctx = python_grammar_loader::load_python_grammar_from_str(&input.grammar_string);
        ctx.initialize(input.generation_depth);
        map.insert(input.grammar_hash.clone(), ctx);
    }
    return map.get(&input.grammar_hash).unwrap().clone();
}

pub fn nautilus_serialize_to_bytes(ctx: &Context, input: &SerializedSeed) -> Result<Vec<u8>, ()> {
    let data = input.tree.unparse_to_vec(ctx);

    // NOTE: HARD LIMIT AT 2MB (REDUNDANT CHECK)
    const MAX_SIZE: usize = 2 << 20;
    if data.len() > MAX_SIZE {
        return Err(());
    }

    Ok(data)
}

pub fn nautilus_serialize_to_ron(input: &SerializedSeed) -> Result<String, ()> {
    let config = PrettyConfig::new()
        .depth_limit(3)
        .new_line("\n".to_string())
        .indentor(" ".to_string());

    match ron::ser::to_string_pretty(input, config) {
            Ok(ser) => {
                // NOTE: HARD LIMIT AT 2MB
                const MAX_SIZE: usize = 2 << 20;
                if ser.len() > MAX_SIZE {
                    return Err(());
                }
                Ok(ser)
            },
            Err(_) => {
                Err(())
            }
    }
}

pub fn nautilus_deserialize_from_ron(input: &[u8]) -> Result<SerializedSeed, ()> {
    let str = String::from_utf8_lossy(input);
    match ron::de::from_str(&str) {
        Ok(ser) => {
            Ok(ser)
        },
        Err(_) => {
            Err(())
        }
    }
}

pub fn nautilus_fuzz_mutate(ctx: &Context, input: &mut SerializedSeed) {
    let mut mutator = Mutator::new(&ctx);

    for _ in 0..6 {
        if let Some(new_tree) = mutator.mutate_tree(&input.tree, &ctx) {
            input.tree = new_tree;
        }
    }
}

pub fn nautilus_fuzz_splice(ctx: &Context, input: &mut SerializedSeed, add_ctx: &Context, add_input: &mut SerializedSeed) {
    let mut mutator = Mutator::new(&ctx);
    if let Some(new_tree) = mutator.splice_trees(&input.tree, ctx, &add_input.tree, add_ctx) {
        input.tree = new_tree;
    }
}

pub fn generic_mutate(in_buffer: &[u8], out_buffer: &mut Vec<u8>, max_size: usize, grammar_to_context_map: &mut HashMap<String, Context>) -> Result<(), ()> {
    let mut input = nautilus_deserialize_from_ron(in_buffer)?;
    if let Ok(token_fuzz) = std::env::var("NAUTILUS_TOKEN_FUZZ") {
        if token_fuzz == "ONLY" {
            if !input.grammar_string.ends_with("# ARTIPHISHELL TOKEN TOKEN TOKEN ") {
                return Err(())
            }
        } else if token_fuzz == "NEVER" {
            if input.grammar_string.ends_with("# ARTIPHISHELL TOKEN TOKEN TOKEN ") {
                return Err(())
            }
        }
    }

    let ctx = get_context_for_input(grammar_to_context_map, &input);
    nautilus_fuzz_mutate(&ctx, &mut input);

    let ron = nautilus_serialize_to_ron(&input)?;
    if ron.len() > max_size {
        return Err(());
    }
    out_buffer.clear();
    out_buffer.reserve(ron.len());
    out_buffer.extend_from_slice(&ron.as_bytes());
    Ok(())
}

pub fn generic_splice(
    in_buffer: &[u8],
    add_buffer: &[u8],
    out_buffer: &mut Vec<u8>,
    max_size: usize,
    grammar_to_context_map: &mut HashMap<String, Context>
) -> Result<(), ()> {
    let mut in_data = nautilus_deserialize_from_ron(in_buffer)?;
    let mut add_data = nautilus_deserialize_from_ron(add_buffer)?;

    // dont splice on different grammars
    if in_data.grammar_hash != add_data.grammar_hash {
        return Ok(())
    }

    let in_ctx = get_context_for_input(grammar_to_context_map, &in_data);
    let add_ctx = get_context_for_input(grammar_to_context_map, &add_data);

    nautilus_fuzz_splice(&in_ctx, &mut in_data, &add_ctx, &mut add_data);

    let ron = nautilus_serialize_to_ron(&in_data)?;
    if ron.len() > max_size {
        return Err(());
    }

    out_buffer.clear();
    out_buffer.reserve(ron.len());
    out_buffer.extend_from_slice(&ron.as_bytes());
    Ok(())
}

pub fn generic_post_process(in_buffer: &[u8], out_buffer: &mut Vec<u8>, grammar_to_context_map: &mut HashMap<String, Context>) -> Result<(), ()> {
    if in_buffer.len() <= 1 {
        out_buffer.clear();
        return Ok(())
    }

    let input = nautilus_deserialize_from_ron(in_buffer)?;
    let ctx = get_context_for_input(grammar_to_context_map, &input);
    let byte_serialized = nautilus_serialize_to_bytes(&ctx, &input)?;
    let size = byte_serialized.len();

    out_buffer.clear();
    out_buffer.reserve(size);
    out_buffer.extend_from_slice(&byte_serialized);
    Ok(())
}


// AFL Mutator Interface
struct NautilusAFLMutator {
    grammar_to_context_map: HashMap<String, Context>,
    buffer: Vec<u8>,
    post_buffer: Vec<u8>,
    _seed: u32
}

impl CustomMutator for NautilusAFLMutator {

    type Error = ();

    fn init(seed: u32) -> Result<Self, ()> {
        pyo3::prepare_freethreaded_python();
        Ok(Self{
            grammar_to_context_map: HashMap::new(),
            buffer: Vec::new(),
            post_buffer: Vec::new(),
            _seed: seed
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, ()> {
        if let Some(add_buff) = add_buff {
            if rand::rng().random_range(0..10) != 0 {
                generic_mutate(&buffer, &mut self.buffer, max_size, &mut self.grammar_to_context_map)?;
            } else {
                generic_splice(&buffer, &add_buff, &mut self.buffer, max_size, &mut self.grammar_to_context_map)?;
            }
        } else {
            generic_mutate(&buffer, &mut self.buffer, max_size, &mut self.grammar_to_context_map)?;
        }
        Ok(Some(self.buffer.as_slice()))
    }

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, ()> {
        generic_post_process(buffer, &mut self.post_buffer, &mut self.grammar_to_context_map)?;
        Ok(Some(self.post_buffer.as_slice()))
    }
}

// Jazzer Mutator Interface
struct NautilusJazzerMutator {
    grammar_to_context_map: HashMap<String, Context>,
    buffer: Vec<u8>,
    post_buffer: Vec<u8>,
    initialized: bool,
    seed: u32
}

impl CustomJazzerMutator for NautilusJazzerMutator {

    type Error = ();

    fn init() -> Result<Self, ()> {
        pyo3::prepare_freethreaded_python();
        Ok(Self{
            grammar_to_context_map: HashMap::new(),
            buffer: Vec::new(),
            post_buffer: Vec::new(),
            initialized: false,
            seed: 0
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b [u8],
        max_size: usize,
        seed: u32
    ) -> Result<Option<&'b [u8]>, ()> {
        if !self.initialized {
            self.seed = seed;
            self.initialized = true;
        }
        generic_mutate(&buffer, &mut self.buffer, max_size, &mut self.grammar_to_context_map)?;
        Ok(Some(self.buffer.as_slice()))
    }

    fn crossover<'b, 's: 'b>(
        &'s mut self,
        buffer1: &'b [u8],
        buffer2: &'b [u8],
        max_size: usize,
        seed: u32
    ) -> Result<Option<&'b [u8]>, ()> {
        if !self.initialized {
            self.seed = seed;
            self.initialized = true;
        }
        generic_splice(&buffer1, &buffer2, &mut self.buffer, max_size, &mut self.grammar_to_context_map)?;
        Ok(Some(self.buffer.as_slice()))
    }

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, ()> {
        generic_post_process(buffer, &mut self.post_buffer, &mut self.grammar_to_context_map)?;
        Ok(Some(self.post_buffer.as_slice()))
    }
}

// Exports
export_afl_mutator!(NautilusAFLMutator);
export_jazzer_mutator!(NautilusJazzerMutator);

#[cfg(test)]
mod tests {
    use grammartec::context::Context;
    use crate::nautilus_deserialize_from_ron;
    use crate::nautilus_serialize_to_bytes;
    use crate::nautilus_serialize_to_ron;
    use crate::nautilus_fuzz_mutate;
    use fuzzer::python_grammar_loader;

    #[test]
    fn test_reload() {
        let mut test_ron = b"(
 seed: None,
 tree: (
  rules: [
   Rule((37)),
   Rule((48)),
   Rule((49)),
   Rule((50)),
   Rule((11)),
   Rule((57)),
   Rule((48)),
   Rule((49)),
   Rule((34)),
   Rule((1)),
   Rule((2)),
   Custom((4), [1]),
   Rule((5)),
   Rule((8)),
   Rule((9)),
   Custom((15), [50]),
   Rule((10)),
   Custom((31), [101, 110, 100]),
   Custom((12), [48]),
   Rule((51)),
   Rule((42)),
   Custom((4), [1]),
   Custom((13), [49]),
  ],
  sizes: [
   23,
   22,
   21,
   20,
   19,
   17,
   16,
   15,
   14,
   13,
   2,
   1,
   10,
   9,
   2,
   1,
   3,
   1,
   1,
   3,
   2,
   1,
   1,
  ],
  paren: [
   (0),
   (0),
   (1),
   (2),
   (3),
   (4),
   (5),
   (6),
   (7),
   (8),
   (9),
   (10),
   (9),
   (12),
   (13),
   (14),
   (13),
   (16),
   (16),
   (13),
   (19),
   (20),
   (4),
  ],
 ),
 generation_index: 0,
 generation_depth: 200,
 grammar_string: \"# Optimized Grammar for JenkinsEmailThree fuzzing harness\n\ndef pack_int(NUM_STAGES: bytes) -> bytes:\n    # Pack an integer into 4 bytes (big-endian)\n    import struct\n    # Using a small, controlled number of stages\n    try:\n        num = int(NUM_STAGES)\n        # Limit to a reasonable range\n        num = max(1, min(num, 10))\n    except ValueError:\n        num = 3  # Default value\n    return struct.pack(\'>i\', num)\n\ndef create_full_input(PACKED_NUM_STAGES: bytes, STAGE_DATA: bytes) -> bytes:\n    # Combine the packed integer with the stage data\n    return PACKED_NUM_STAGES + STAGE_DATA\n\n# Main entry point for the fuzzer\nctx.rule(\\\"START\\\", b\\\"{FULL_INPUT}\\\")\n\n# Create the full input by combining the number of stages and the stage data\nctx.script(\\\"FULL_INPUT\\\", [\\\"PACKED_NUM_STAGES\\\", \\\"STAGE_DATA\\\"], create_full_input)\n\n# Pack the number of stages as a 4-byte integer\nctx.script(\\\"PACKED_NUM_STAGES\\\", [\\\"NUM_STAGES\\\"], pack_int)\n\n# Generate values for NUM_STAGES - focusing on small numbers for targeted testing\nctx.literal(\\\"NUM_STAGES\\\", b\\\"2\\\")\nctx.literal(\\\"NUM_STAGES\\\", b\\\"3\\\")\n\n# Generate stages with controlled values\nctx.rule(\\\"STAGE_DATA\\\", b\\\"{STAGE_SEQUENCE}\\\")\n\n# Different sequences of stages to try\n# CRITICAL: We need a sequence that sets emailAddress to \\\"getEmail\\\" and publishReady to true\n# The first stage value is used as emailAddress, and a \\\"finished\\\" stage sets publishReady to true\nctx.rule(\\\"STAGE_SEQUENCE\\\", b\\\"{EMAIL_ADDRESS_STAGE}{PUBLISH_READY_STAGE}\\\")\nctx.rule(\\\"STAGE_SEQUENCE\\\", b\\\"{EMAIL_ADDRESS_STAGE}{MIDDLE_STAGE}{PUBLISH_READY_STAGE}\\\")\nctx.rule(\\\"STAGE_SEQUENCE\\\", b\\\"{EMAIL_ADDRESS_STAGE}{PUBLISH_READY_STAGE}{MIDDLE_STAGE}\\\")\n\n# Define the email address stage - MUST be \\\"getEmail\\\" to call the target function\nctx.rule(\\\"EMAIL_ADDRESS_STAGE\\\", b\\\"getEmail\\\\0{JUMP_VALUE}\\\\0\\\")\n\n# Define the publish ready stage - needs to set publishReady to true\nctx.rule(\\\"PUBLISH_READY_STAGE\\\", b\\\"{FINISHED_VALUE}\\\\0{JUMP_VALUE}\\\\0\\\")\n\n# Define middle stages (less important for this specific target)\nctx.rule(\\\"MIDDLE_STAGE\\\", b\\\"{STAGE_VALUE}\\\\0{JUMP_VALUE}\\\\0\\\")\n\n# Jump values - including a variety to ensure we can navigate stages properly\nctx.literal(\\\"JUMP_VALUE\\\", b\\\"0\\\")\nctx.literal(\\\"JUMP_VALUE\\\", b\\\"1\\\")\nctx.literal(\\\"JUMP_VALUE\\\", b\\\"-1\\\")\nctx.literal(\\\"JUMP_VALUE\\\", b\\\"2\\\")\nctx.literal(\\\"JUMP_VALUE\\\", b\\\"-2\\\")\n\n# Regular stage values (less important for this specific target)\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"process\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"continue\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"running\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"active\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"verify\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"pending\\\")\nctx.literal(\\\"STAGE_VALUE\\\", b\\\"waiting\\\")\n\n# Values to trigger \\\"finished\\\" state and set publishReady to true\n# These are critical for setting publishReady=true\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"finished\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"complete\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"done\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"success\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"ready\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"email_ready\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"publish_ready\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"end\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"final\\\")\nctx.literal(\\\"FINISHED_VALUE\\\", b\\\"completed\\\")\n\",
 grammar_hash: \"c9da92662efbdca3e750a36e524e9310\"
)";

        pyo3::prepare_freethreaded_python();

        let mut ctx = Context::new();
        let mut input = nautilus_deserialize_from_ron(test_ron).unwrap();
        let mut ctx = python_grammar_loader::load_python_grammar_from_str(&input.grammar_string);
        ctx.initialize(input.generation_depth);

        for _ in 0..50 {
            for _ in 0..10 {
                nautilus_fuzz_mutate(&ctx, &mut input);
            }

            // save original byte representation
            let bytes = nautilus_serialize_to_bytes(&ctx, &mut input).unwrap();

            // convert serialized input to ron
            let mutated_ron_string = nautilus_serialize_to_ron(&input).unwrap();

            // go back from ron to serialized input
            let mut input_mutated = nautilus_deserialize_from_ron(&mutated_ron_string.bytes().collect::<Vec<u8>>()).unwrap();
            let mut mutated_ctx = python_grammar_loader::load_python_grammar_from_str(&input.grammar_string);
            mutated_ctx.initialize(input.generation_depth);

            // convert mutated input to bytes
            let mutated_bytes = nautilus_serialize_to_bytes(&mutated_ctx, &mut input_mutated).unwrap();

            assert_eq!(bytes, mutated_bytes);
        }
    }
}
