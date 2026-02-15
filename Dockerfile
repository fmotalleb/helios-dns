FROM library/debian:trixie-slim
COPY helios-dns /usr/local/bin
ENTRYPOINT ["helios-dns"]
