FROM scratch
COPY go-selfupdate /
ENTRYPOINT ["/go-selfupdate"]