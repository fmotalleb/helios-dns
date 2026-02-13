FROM scratch
COPY helios-dns /
ENTRYPOINT ["/helios-dns"]
