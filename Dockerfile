FROM ubuntu:22.04

# Install build tools
RUN apt-get update && apt-get install -y gcc make && rm -rf /var/lib/apt/lists/*

# Copy project
WORKDIR /app
COPY . .

# Build
RUN make clean && make

# Run with creative intro
CMD ["bash", "./run.sh"]
