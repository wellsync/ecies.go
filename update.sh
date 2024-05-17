#!/bin/sh

VERSION="1.14.3"

if ! [ -d "/tmp/go-eth" ]; then
  git clone git@github.com:ethereum/go-ethereum.git /tmp/go-eth
fi

(cd /tmp/go-eth && git fetch --tags && git checkout v${VERSION}) && \
    cp /tmp/go-eth/crypto/ecies/* ./