FROM rust AS builder
LABEL builder=true

# copy code files
COPY Cargo.toml Cargo.lock /code/
COPY /src/ /code/src/

# build code
WORKDIR /code
RUN cargo build --release

# runtime container
FROM debian:11 AS runtime
LABEL builder=false

# set default logging, can be overridden
ENV RUST_LOG=info

# copy binary
COPY --from=builder /code/target/release/dnstotp /usr/local/bin/dnstotp

EXPOSE 53/udp

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnstotp"]
