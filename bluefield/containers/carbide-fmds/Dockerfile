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

# Runtime image for carbide-fmds on arm64 DPUs.
#
# The binary is cross-compiled externally using the
# build-artifacts-container-cross-aarch64 image and copied into this
# minimal runtime container.

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG RUNTIME_IMAGE=nvcr.io/nvidia/distroless/cc:v3.2.1-dev@sha256:3f6fe2b7e87f25d8c665d2caf80763ca691a1a6dfd2ac5a6b6f14c161108f0d4

FROM --platform=linux/arm64 ${DEBIAN_IMAGE} AS builder

# Get Unbound and its control tools from the same Debian release as
# the agent image, which validates configurations and requests reloads.
RUN apt-get update && apt-get install -y --no-install-recommends unbound
RUN mkdir -p /deps && \
    ldd /usr/sbin/unbound /usr/sbin/unbound-checkconf /usr/sbin/unbound-control \
      | awk '$2 == "=>" && $3 ~ /^\// { print $3 }' \
      | sort -u | xargs -r cp -t /deps/

FROM --platform=linux/arm64 ${RUNTIME_IMAGE}

COPY --from=builder /usr/sbin/unbound /usr/sbin/unbound-checkconf /usr/sbin/unbound-control /usr/sbin/
COPY --from=builder /deps/ /lib/

COPY --chmod=755 target/aarch64-unknown-linux-gnu/release/carbide-fmds /usr/bin/carbide-fmds

ENTRYPOINT ["/usr/bin/carbide-fmds"]
