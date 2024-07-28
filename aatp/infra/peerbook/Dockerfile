FROM golang:alpine
ARG REF=master
RUN apk update
RUN apk add git bash
RUN addgroup -S peerbook && adduser -S peerbook -G peerbook
ENV PB_STATIC_ROOT=/home/peerbook/src/peerbook/html
EXPOSE 17777
WORKDIR /peerbook
CMD go run . -addr peerbook:17777
