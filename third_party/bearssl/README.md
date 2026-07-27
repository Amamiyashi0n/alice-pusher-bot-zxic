# BearSSL minimal source subset

This directory contains the unmodified BearSSL 0.6 headers and only the C
sources needed by Alice Pusher Bot's fixed outbound HTTPS and SMTP TLS profile.
The selected source list is maintained in `tools/bearssl_sources.sh`. These
sources build as a standalone `libbearssl.so.0`; application transport code is
kept outside the library. The profile supports TLS 1.2 ECDHE-RSA and RSA key
exchange with AES-128-GCM/CBC.

BearSSL is Copyright (c) 2016 Thomas Pornin and distributed under the MIT
license in `LICENSE.txt`.
