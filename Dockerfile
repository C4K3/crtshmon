FROM rust:1.56.0 AS build

RUN mkdir /build
WORKDIR /build
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./src ./src
RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends dumb-init ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/crtshmon /bin/crtshmon
RUN useradd --create-home --user-group crtshmon
USER crtshmon
WORKDIR /home/crtshmon
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/bin/crtshmon"]
