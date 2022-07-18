# This Dockerfile isn't build for speed, but for debugging purposes. So
# it tries to cache as much as possible with the downside that the image
# size is probably going to be huge.
#
# Change where needed when you want to re-use this on your production
# server

FROM perl:latest

WORKDIR /tmp/build

ENV DEBIAN_FRONTEND=noninteractive \
    NO_NETWORK_TESTING=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libxml2-dev \
    xmlsec1 \
    openssl \
    libexpat1-dev

COPY dev-bin/cpanm .
RUN ./cpanm Moose

COPY cpanfile .
RUN ./cpanm --installdeps .

COPY . .

RUN prove -lv
RUN ./cpanm --test-only .
RUN perl Makefile.PL && make && make test
