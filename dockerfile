FROM mhub/base-go
COPY actest-linux-amd64 /actest
ENTRYPOINT ["/actest"]