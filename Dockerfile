FROM rustlang/rust:nightly
WORKDIR /app

COPY ./ ./

RUN apt-get update \
    && apt-get install -y --no-install-recommends zip \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

CMD ["./target/release/meticulous-telemetry-server"]
