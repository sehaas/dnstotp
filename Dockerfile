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

RUN apt-get update && apt-get -y install bind9-dnsutils && apt-get clean

# set default logging, can be overridden
ENV RUST_LOG=info
ENV DNSTOTP_DB=/data
ENV DNSTOTP_ZONE=otp.example.com
ENV DNSTOTP_NS=ns1.example.com

# copy binary
COPY --from=builder /code/target/release/dnstotp /usr/local/bin/dnstotp

EXPOSE 1053/udp

# set entrypoint
ENTRYPOINT /usr/local/bin/dnstotp --database "${DNSTOTP_DB}" --dns-zone "${DNSTOTP_ZONE}" --nameserver "${DNSTOTP_NS}" 
