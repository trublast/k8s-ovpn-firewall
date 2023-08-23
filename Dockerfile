FROM golang:1.19.4-alpine3.16 AS build-stage
ADD . build
RUN apk update && apk add binutils && cd build && ls -la && go mod tidy && go build -o firewall && ls -lah firewall && strip firewall && ls -lah firewall 

FROM alpine:3.16 AS export-stage
RUN apk add iptables ipset --no-cache
COPY --from=build-stage /go/build/firewall /
CMD /firewall