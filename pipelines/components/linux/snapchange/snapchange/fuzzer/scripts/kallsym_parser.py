#!/usr/bin/python3
# Define the input and output filenames
input_filename = './rtk.adr'
output_filename = './rtk_output.adr'

# Read from the input file
with open(input_filename, 'r') as infile:
    lines = infile.readlines()

# Process the data
output_data = []
for line in lines:
    parts = line.split()
    if parts:
        address = parts[0]
        output_data.append(f'0x{address}')

# Write the results to the output file
with open(output_filename, 'w') as outfile:
    outfile.write('\n'.join(output_data))

print(f"Results written to {output_filename}")
