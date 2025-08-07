# Use a base image with GDB installed
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    gdb \
    build-essential

# Copy source files and Makefile into the container
COPY . /src

# Set working directory
WORKDIR /src

# Build the binary
RUN make

# Create a directory for the socket
RUN mkdir -p /tmp/gdb

# Command to start GDB server
CMD ["gdbserver", "--multi", "/tmp/gdb/gdbsocket", "/src/mock_vp"]