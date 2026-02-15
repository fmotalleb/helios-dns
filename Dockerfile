FROM library/debian:trixie-slim
COPY helios-dns /
ENTRYPOINT ["/helios-dns"]
