# syntax=docker/dockerfile:1
FROM python:3.10-slim-buster AS pythonbuilder
ENV PYTHONUNBUFFERED 1
RUN pip install requests
RUN pip install lxml
RUN mkdir /scripts
RUN mkdir /internal
COPY ./scripts/ /scripts/
COPY ./internal/ /internal/
WORKDIR /scripts/pks1
RUN ./dl_all_pks1.py
WORKDIR /scripts/pks2
RUN ./dl_all_pks2.py

FROM golang:1.19 AS gobuilder
WORKDIR /go/src/github.com/kyburz-switzerland-ag/tachoparser
COPY ./ ./
COPY --from=pythonbuilder /internal/pkg/certificates/pks1/ internal/pkg/certificates/pks1/
COPY --from=pythonbuilder /internal/pkg/certificates/pks2/ internal/pkg/certificates/pks2/
RUN go mod vendor
WORKDIR /go/src/github.com/kyburz-switzerland-ag/tachoparser/cmd/dddparser
RUN go build .
WORKDIR /go/src/github.com/kyburz-switzerland-ag/tachoparser/cmd/dddserver
RUN go build .
WORKDIR /go/src/github.com/kyburz-switzerland-ag/tachoparser/cmd/dddclient
RUN go build .

FROM scratch
COPY --from=gobuilder /bin/dash /bin/sh
COPY --from=gobuilder /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=gobuilder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=gobuilder /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/
COPY --from=gobuilder /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/
COPY --from=gobuilder /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/
# COPY --from=gobuilder /lib/x86_64-linux-gnu/libnss*.so.? /lib/x86_64-linux-gnu/
COPY --from=gobuilder /etc/ssl/certs/* /etc/ssl/certs/
COPY --from=gobuilder /usr/share/zoneinfo/* /usr/share/zoneinfo/
COPY --from=gobuilder /go/src/github.com/kyburz-switzerland-ag/tachoparser/cmd/dddserver/dddserver /dddserver
ENTRYPOINT ["/dddserver"]
CMD []