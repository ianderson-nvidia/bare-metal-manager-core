# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runtime image for forge-dpu-agent on arm64 DPUs.
#
# The binary is cross-compiled externally using the
# build-artifacts-container-cross-aarch64 image and copied into this
# minimal runtime container.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG RUNTIME_IMAGE=nvcr.io/nvidia/distroless/cc:v3.2.1-dev@sha256:3f6fe2b7e87f25d8c665d2caf80763ca691a1a6dfd2ac5a6b6f14c161108f0d4

# Stage 1

FROM --platform=linux/arm64 ${DEBIAN_IMAGE} AS builder

# Get libraries and install MFT (provides flint for DPU firmware enumeration)
RUN apt-get update && apt-get install -y \
     libudev1 \
     bash \
     unbound

# Working flint extraction
COPY mft-4.35.0-159-aarch64-deb/DEBS/mft_4.35.0-159_arm64.deb /tmp/mstflint.deb
RUN mkdir -p /extract && dpkg-deb -x /tmp/mstflint.deb /extract
RUN mkdir -p /deps && \
    # Locate the binary (usually in /usr/bin/ inside the extraction folder)
    BINARY_PATH=$(find /extract -name flint -o -name mstflint | head -n 1) && \
    # Use ldd to find dependencies, but point it to the libraries in the extraction folder if needed
    ldd $BINARY_PATH | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp -v '{}' /deps/

# Setup directory to collect all shared libraries
RUN mkdir -p /deps && \
    cp $(ldd /bin/bash | grep "=> /" | awk '{print $3}') /deps/

# The agent validates files and reloads the resolver through its Unix socket.
# Copy the tools' complete dependency set; they run without a Debian rootfs.
RUN ldd /usr/sbin/unbound-checkconf /usr/sbin/unbound-control \
      | awk '$2 == "=>" && $3 ~ /^\// { print $3 }' \
      | sort -u | xargs -r cp -t /deps/

# Stage 2
FROM --platform=linux/arm64 ${RUNTIME_IMAGE}

# Copy bash binary, libraries, and mft from builder
COPY --from=builder /lib/aarch64-linux-gnu/libudev.so.1 /lib/aarch64-linux-gnu/libudev.so.1
COPY --from=builder --chmod=755 /bin/bash /bin/bash
COPY --from=builder --chmod=755 /extract/usr/bin/ /usr/bin/
COPY --from=builder /deps/* /lib/
COPY --from=builder /usr/sbin/unbound-checkconf /usr/sbin/unbound-control /usr/sbin/

# Copy forge-dpu-agent and set entry point
COPY --chmod=755 target/aarch64-unknown-linux-gnu/release/forge-dpu-agent /usr/bin/forge-dpu-agent

ENTRYPOINT ["/usr/bin/forge-dpu-agent"]
