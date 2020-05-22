# This Dockerfile isn't build for speed, but for debugging purposes. So
# it tries to cache as much as possible with the downside that the image
# size is probably going to be huge.
#
# Change where needed when you want to re-use this on your production
# server

FROM perl:slim-stretch

WORKDIR /tmp/build

ENV DEBIAN_FRONTEND=noninteractive \
    NO_NETWORK_TESTING=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    gcc \
# libssl1.0-dev is required, because Crypt::OpenSSL::{X509,RSA,VerifyX509} do not
# support libssl1.1 yet.
# It can be removed once
# https://github.com/dsully/perl-crypt-openssl-x509/issues/53 and related bugs
# for the other projects are fixed.
    libssl1.0-dev \
    libxml2-dev \
    xmlsec1 \
    openssl \
    libexpat1-dev

COPY dev-bin/cpanm .
RUN ./cpanm Moose

COPY cpanfile .

RUN ./cpanm --installdeps .

# A newer version of Crypt::OpenSSL::RSA has been released on may 31st
# 2018. This breaks Net::SAML2. Force it at 0.28 for the time being
#RUN ./cpanm "Crypt::OpenSSL::RSA@0.28"

COPY . .

RUN prove -lv

RUN ./cpanm --test-only .

RUN perl Makefile.PL && make && make test
