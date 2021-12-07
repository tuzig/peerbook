FROM golang:1.16-buster as builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN go build -v -o peerbook
# get chmaber

RUN apt-get update && apt-get install -y curl && \
    curl -o chamber -LOs https://github.com/segmentio/chamber/releases/download/v2.10.6/chamber-v2.10.6-linux-amd64 && \
    chmod 755 chamber && \
    ./chamber version

# Use the official Debian slim image for a lean production container.
# https://hub.docker.com/_/debian
# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds
FROM debian:buster-slim
ENV LAYER_NAME=""
WORKDIR /app
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/peerbook /app/peerbook
COPY --from=builder /app/chamber /usr/local/bin

CMD /usr/local/bin/chamber exec "${LAYER_NAME}" -- /app/peerbook
