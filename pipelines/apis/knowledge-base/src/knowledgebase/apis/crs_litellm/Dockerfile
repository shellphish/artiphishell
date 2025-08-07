# Use an official Python runtime as a parent image
FROM python:3.11.8-slim

# Set the working directory in the container
WORKDIR /app

# Install Node.js, npm, and dependencies for Rust and Python builds
RUN apt-get update && \
    apt-get install -y nodejs npm curl build-essential libpq-dev && \
    apt-get clean

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set the environment variables for Rust
ENV PATH="/root/.cargo/bin:${PATH}"

# Source the Rust environment (ensure Rust is available in this shell)
RUN /bin/bash -c "source $HOME/.cargo/env"

# Install Prisma CLI
RUN npm install -g prisma@4.5.0 --force

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV DATABASE_URL="postgresql://llmuser:artiphishell@db:5432/llmdb"
ENV LITELLM_VERIFICATION_TOKEN="artiphishell!!"
ENV LITELLM_MASTER_KEY="sk-artiphishell"

# Copy the entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose the port that the app runs on
EXPOSE 4000

# Run the app with the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
