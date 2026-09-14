# FreeSCP release build image.
#
# One arch-agnostic image covers all six release targets:
#   - linux-x86_64 / linux-aarch64 : compiled natively inside a container whose
#     --platform matches the target (driver script picks the platform; on an
#     amd64 CI runner the aarch64 container runs under QEMU binfmt).
#   - macos-x86_64 / macos-arm64   : cross-compiled with cargo-zigbuild + zig.
#   - windows-x86_64 / windows-arm64: cross-compiled with llvm-mingw against the
#     *-pc-windows-gnullvm Rust targets.
#
# The repo is mounted at /work at run time (never COPYied), so image layers only
# contain toolchains and stay cacheable across releases.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# Pinned toolchain versions (upgrade deliberately, not incidentally).
ENV LLVM_MINGW_VERSION=20251216
ENV ZIG_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      python3 \
      python3-pip \
      build-essential \
      pkg-config \
      file \
      zip \
      unzip \
      xz-utils \
      libssl-dev \
      libxkbcommon-dev \
      libxkbcommon-x11-dev \
      libfontconfig1-dev \
      libgtk-3-dev \
      libgl1-mesa-dev \
      libxcb1-dev \
      libxcb-render0-dev \
      libxcb-shape0-dev \
      libxcb-xfixes0-dev \
      libxkbcommon0 \
      libxkbcommon-x11-0 \
      libfontconfig1 \
      libwayland-client0 \
      libgl1 \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/root/.local/bin:$PATH

# Minimal profile: no docs, no clippy/rustfmt (CI uses the plain ci.yml image).
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal \
    && rustup target add \
      x86_64-unknown-linux-gnu \
      aarch64-unknown-linux-gnu \
      x86_64-apple-darwin \
      aarch64-apple-darwin \
      x86_64-pc-windows-gnullvm \
      aarch64-pc-windows-gnullvm

# cargo-zigbuild + zig: macOS cross-linker (handles -framework for
# AppKit/CoreFoundation/Security/OpenGL pulled in by winit/objc2/ring).
RUN cargo install --locked cargo-zigbuild \
    && pip3 install "ziglang==${ZIG_VERSION}"

# llvm-mingw: clang/lld/windres for the Windows gnullvm targets.
RUN arch="$(uname -m)" \
    && case "$arch" in \
         x86_64)  a=x86_64  ;; \
         aarch64) a=aarch64 ;; \
         *) echo "unsupported container arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL -o /tmp/llvm-mingw.tar.xz \
      "https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VERSION}/llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-${a}.tar.xz" \
    && tar -xJf /tmp/llvm-mingw.tar.xz -C /opt \
    && mv "/opt/llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-${a}" /opt/llvm-mingw \
    && rm /tmp/llvm-mingw.tar.xz

ENV PATH=/opt/llvm-mingw/bin:$PATH

# macOS SDK (framework/linker stubs) so zig can link AppKit, CoreFoundation,
# OpenGL, Security, ... The SDK is not redistributable by toolchains, so pull
# the community-maintained SDK snapshot the cross-compile ecosystem uses.
ENV MACOS_SDK_VERSION=11.3
RUN curl -fsSL -o /tmp/macos-sdk.tar.xz \
      "https://github.com/phracker/MacOSX-SDKs/releases/download/${MACOS_SDK_VERSION}/MacOSX${MACOS_SDK_VERSION}.sdk.tar.xz" \
    && mkdir -p /opt/macos-sdk \
    && tar -xJf /tmp/macos-sdk.tar.xz -C /opt/macos-sdk \
    && rm /tmp/macos-sdk.tar.xz

ENV SDKROOT=/opt/macos-sdk/MacOSX11.3.sdk \
    MACOSX_DEPLOYMENT_TARGET=11.0

# Linker/archive/C defaults for the Windows gnullvm targets (llvm-mingw tools).
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-gcc \
    CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=aarch64-w64-mingw32-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_AR=x86_64-w64-mingw32-ar \
    CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_AR=aarch64-w64-mingw32-ar \
    CC_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-gcc \
    CC_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-gcc \
    AR_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-ar \
    AR_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-ar

# The repo mount is owned by the host user; git inside build.rs would refuse it.
RUN git config --global --add safe.directory '*'

WORKDIR /work
