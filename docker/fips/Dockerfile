# A FIPS-capable OpenSSL for testing `mls-tls --features fips`.
#
# Builds OpenSSL with `enable-fips`, runs `openssl fipsinstall` to generate the module's self-test
# data, and wires up an openssl.cnf that makes the module *available* without activating it —
# `mls_tls::fips::enable()` loads it programmatically instead.
#
#   docker build -t mls-tls-fips docker/fips
#   docker run --rm -v "$PWD:/src" -w /src mls-tls-fips \
#       cargo test --no-default-features --features fips
#
# This module is self-built and therefore NOT a CMVP-validated configuration. It is the right tool
# for checking that the code behaves correctly in FIPS mode; it is not evidence of compliance.

FROM rust:1-bookworm

# 3.5 is the floor: older FIPS modules reject the short HKDF-Expand outputs MLS uses for every AEAD
# nonce (see src/fips.rs). Bump freely within 3.5+.
ARG OPENSSL_VERSION=3.5.0
ENV OPENSSL_PREFIX=/opt/openssl-fips

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && tar xzf "openssl-${OPENSSL_VERSION}.tar.gz" \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure enable-fips \
        --prefix="${OPENSSL_PREFIX}" \
        --openssldir="${OPENSSL_PREFIX}/ssl" \
        --libdir=lib \
    && make -j"$(nproc)" \
    && make install_sw install_ssldirs install_fips \
    && cd / && rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"

# Generate the module's integrity/self-test data, then strip `activate = 1`.
#
# This is not cosmetic. fips_module(7) is explicit that for programmatic loading the activate line
# must be ABSENT — setting it to 0 is not sufficient. Leaving it in would activate the module at
# library init, which defeats the point of controlling the ordering from `enable()`.
#
# LD_LIBRARY_PATH is set inline because the ENV below has not taken effect yet: without it the
# freshly built binary resolves against Debian's system libcrypto 3.0 and fails on missing symbol
# versions.
RUN LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib" "${OPENSSL_PREFIX}/bin/openssl" fipsinstall \
        -out "${OPENSSL_PREFIX}/ssl/fipsmodule.cnf" \
        -module "${OPENSSL_PREFIX}/lib/ossl-modules/fips.so" \
    && sed -i '/^activate\s*=/d' "${OPENSSL_PREFIX}/ssl/fipsmodule.cnf"

COPY openssl.cnf /tmp/openssl.cnf
RUN sed "s|@PREFIX@|${OPENSSL_PREFIX}|g" /tmp/openssl.cnf > "${OPENSSL_PREFIX}/ssl/openssl.cnf" \
    && rm /tmp/openssl.cnf

# Point both the openssl CLI and openssl-sys at this build.
ENV OPENSSL_DIR=${OPENSSL_PREFIX} \
    OPENSSL_CONF=${OPENSSL_PREFIX}/ssl/openssl.cnf \
    LD_LIBRARY_PATH=${OPENSSL_PREFIX}/lib \
    PATH=${OPENSSL_PREFIX}/bin:$PATH

# Fail the image build if the module is not loadable, rather than at test time.
RUN openssl list -providers -provider fips > /dev/null \
    && echo "FIPS provider loads OK"

WORKDIR /src
CMD ["cargo", "test", "--no-default-features", "--features", "fips"]
