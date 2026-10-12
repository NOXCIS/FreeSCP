# FreeSCP Linux UI audit image: Slint build deps + Xvfb + optional VNC + screenshot tools.
# Used by scripts/docker-ui-screenshots.sh — not the release packaging image.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    DISPLAY=:99

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      build-essential \
      pkg-config \
      clang \
      libclang-dev \
      libssl-dev \
      libxkbcommon-dev \
      libxkbcommon-x11-dev \
      libfontconfig1-dev \
      libgtk-3-dev \
      libgl1-mesa-dev \
      libegl1-mesa-dev \
      mesa-utils \
      libxcb1-dev \
      libxcb-render0-dev \
      libxcb-shape0-dev \
      libxcb-xfixes0-dev \
      libxcb-cursor0 \
      libwayland-dev \
      xvfb \
      x11vnc \
      xdotool \
      scrot \
      imagemagick \
      fonts-dejavu-core \
      dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal \
    && rustup component add rustfmt clippy \
    && git config --global --add safe.directory '*'

WORKDIR /work
