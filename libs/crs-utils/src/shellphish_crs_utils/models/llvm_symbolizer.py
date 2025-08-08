# [
#     {
#         "Address": "0x2915e0",
#         "ModuleName": "/out/njs_process_script_fuzzer",
#         "Symbol": [
#             {
#                 "Column": 0,
#                 "Discriminator": 0,
#                 "FileName": "/src/njs/external/njs_shell.c",
#                 "FunctionName": "LLVMFuzzerTestOneInput",
#                 "Line": 855,
#                 "StartAddress": "0x2915e0",
#                 "StartFileName": "",
#                 "StartLine": 0
#             }
#         ]
#     }
# ]

# [
#   {
#     "Address": "0x291915",
#     "ModuleName": "./njs_process_script_fuzzer",
#     "Symbol": [
#       {
#         "Column": 5,
#         "Discriminator": 0,
#         "FileName": "/src/njs/external/njs_shell.c",
#         "FunctionName": "njs_read_file",
#         "Line": 3186,
#         "StartAddress": "",
#         "StartFileName": "",
#         "StartLine": 0
#       },
#       {
#         "Column": 11,
#         "Discriminator": 0,
#         "FileName": "/src/njs/external/njs_shell.c",
#         "FunctionName": "njs_process_file",
#         "Line": 3285,
#         "StartAddress": "",
#         "StartFileName": "",
#         "StartLine": 0
#       },
#       {
#         "Column": 15,
#         "Discriminator": 0,
#         "FileName": "/src/njs/external/njs_shell.c",
#         "FunctionName": "njs_main",
#         "Line": 458,
#         "StartAddress": "",
#         "StartFileName": "",
#         "StartLine": 0
#       },
#       {
#         "Column": 12,
#         "Discriminator": 0,
#         "FileName": "/src/njs/external/njs_shell.c",
#         "FunctionName": "LLVMFuzzerTestOneInput",
#         "Line": 869,
#         "StartAddress": "0x2915e0",
#         "StartFileName": "",
#         "StartLine": 0
#       }
#     ]
#   }
# ]

import json
import os
from typing import List, Tuple, TypeAlias
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.symbols import BinaryLocation, SourceLocation

class LLVMSymbolizerSymbol(ShellphishBaseModel):
    Column: int
    Discriminator: int
    FileName: str
    FunctionName: str
    Line: int
    StartAddress: str
    StartFileName: str
    StartLine: int

    @property
    def was_inlined(self) -> bool:
        return not bool(self.StartAddress)

    def to_location(self) -> SourceLocation:
        return SourceLocation(
            full_file_path=self.FileName,
            file_name = os.path.basename(self.FileName),
            function_name=self.FunctionName,
            line_number=self.Line,
            symbol_offset=int(self.StartAddress, 16),
        )

class LLVMSymbolizerEntry(ShellphishBaseModel):
    Address: str
    ModuleName: str

    # in the case of inlines there can be multiple symbols for a given binary location
    Symbol: List[LLVMSymbolizerSymbol]

    def get_locations(self) -> Tuple[BinaryLocation, List[SourceLocation]]:
        binary_location = BinaryLocation.create(
            full_binary_path=self.ModuleName,
            offset=int(self.Address, 16),
        )
        source_locs = [
            symbol.to_location()
            for symbol in self.Symbol
        ]
        assert all(loc.was_inlined for loc in self.Symbol[:-1]), f"Only the last symbol can be non-inlined: {self.Symbol}, {source_locs}"
        assert not source_locs or not self.Symbol[-1].was_inlined, f"The last symbol should never be inlined: {self.Symbol}, {source_locs}"
        return binary_location, source_locs

LLVMSymbolizerList: TypeAlias = List[LLVMSymbolizerEntry]

def parse_llvm_symbolizer_json_output_string(output: str) -> LLVMSymbolizerList:
    parsed = json.loads(output)
    symbols = [LLVMSymbolizerEntry.model_validate(entry) for entry in parsed]
    return symbols

def parse_llvm_symbolizer_json_output_file(file_path: str) -> LLVMSymbolizerList:
    with open(file_path, 'r') as f:
        parsed = json.load(f)
    symbols = [LLVMSymbolizerEntry.model_validate(entry) for entry in parsed]
    return symbols
    