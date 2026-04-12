# Stage 1: Build
FROM gcc:13-bookworm AS builder

WORKDIR /app

# Copy source files
COPY src/ ./src/
COPY include/ ./include/
COPY config/ ./config/
COPY Makefile .

# Build the binary
RUN make all

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Copy compiled binary and config
COPY --from=builder /app/scd ./scd
COPY --from=builder /app/config ./config

# Default: show help
ENTRYPOINT ["./scd"]
CMD ["--help"]
