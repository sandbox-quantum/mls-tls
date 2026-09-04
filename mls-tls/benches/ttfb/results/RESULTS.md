# mls-tls TTFB benchmark results

Time to first application byte, swept across simulated RTTs (loopback TCP through a latency-injecting relay). `min` is the fastest sample in ms; `flights` is the recovered round-trip count at the top RTT. Expected flights: handshake 4, key-update 2, mls-tls resumption 2, openssl `resumption-0rtt` 2 (TLS 1.3 early data), openssl `resumption-1rtt` 4 (replay-safe session-ticket resumption).

## OpenSSL-backend comparison: mls-tls vs the OpenSSL TLS 1.3 stack

Both stacks built with `--features openssl`. request 39 B, response 40 B; up to 10 iters/cell within a 5s budget.

| suite | scenario | stack | 0ms | 1ms | 10ms | 50ms | 100ms | 250ms | 500ms | 1000ms | 2000ms | 3000ms | flights |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p256 | handshake | mls-tls | 1.19 | 3.19 | 21.77 | 101.80 | 202.48 | 503.74 | 1005.27 | 2002.31 | 4002.62 | 6003.48 | 4.00 |
| p256 | handshake | openssl | 0.82 | 3.19 | 21.54 | 101.86 | 202.61 | 502.46 | 1001.84 | 2004.53 | 4004.51 | 6003.02 | 4.00 |
| p256 | key-update | mls-tls | 1.27 | 2.25 | 11.79 | 51.73 | 102.44 | 253.15 | 502.87 | 1003.95 | 2003.42 | 3003.24 | 2.00 |
| p256 | key-update | openssl | 0.12 | 1.20 | 10.34 | 50.50 | 100.41 | 250.62 | 500.53 | 1000.52 | 2000.55 | 3000.73 | 2.00 |
| p256 | resumption | mls-tls | 1.22 | 2.27 | 11.63 | 51.81 | 103.14 | 252.26 | 502.07 | 1001.81 | 2002.43 | 3003.92 | 2.00 |
| p256 | resumption-0rtt | openssl | 0.44 | 1.55 | 10.84 | 51.29 | 101.28 | 251.37 | 501.63 | 1001.59 | 2001.67 | 3001.92 | 2.00 |
| p256 | resumption-1rtt | openssl | 0.66 | 2.67 | 20.90 | 101.49 | 201.60 | 502.06 | 1001.99 | 2001.94 | 4002.01 | 6002.32 | 4.00 |
| p384 | handshake | mls-tls | 3.54 | 5.60 | 23.93 | 109.39 | 207.05 | 509.90 | 1013.76 | 2015.01 | 4013.09 | 6010.91 | 4.00 |
| p384 | handshake | openssl | 1.18 | 3.26 | 21.40 | 101.89 | 202.92 | 503.52 | 1004.17 | 2002.47 | 4002.20 | 6005.31 | 4.00 |
| p384 | key-update | mls-tls | 2.85 | 4.09 | 13.08 | 53.20 | 104.63 | 255.84 | 506.00 | 1006.11 | 2010.28 | 3009.53 | 2.00 |
| p384 | key-update | openssl | 0.14 | 1.17 | 10.23 | 50.36 | 100.39 | 250.46 | 500.58 | 1000.79 | 2000.54 | 3000.88 | 2.00 |
| p384 | resumption | mls-tls | 2.83 | 3.93 | 12.98 | 53.39 | 104.57 | 256.41 | 506.09 | 1006.80 | 2006.75 | 3007.34 | 2.00 |
| p384 | resumption-0rtt | openssl | 0.92 | 1.95 | 11.19 | 51.57 | 101.83 | 252.01 | 502.05 | 1003.06 | 2004.09 | 3004.21 | 2.00 |
| p384 | resumption-1rtt | openssl | 1.43 | 3.22 | 21.65 | 102.35 | 204.11 | 503.29 | 1004.37 | 2003.65 | 4002.51 | 6004.29 | 4.00 |
| x25519 | handshake | mls-tls | 2.00 | 3.98 | 22.24 | 104.18 | 203.56 | 503.74 | 1004.84 | 2007.24 | 4005.29 | 6005.59 | 4.00 |
| x25519 | handshake | openssl | 0.82 | 2.62 | 20.75 | 101.56 | 201.75 | 501.62 | 1001.92 | 2002.46 | 4002.71 | 6002.36 | 4.00 |
| x25519 | key-update | mls-tls | 1.32 | 2.41 | 11.50 | 51.58 | 102.45 | 253.55 | 502.77 | 1004.08 | 2004.21 | 3006.27 | 2.00 |
| x25519 | key-update | openssl | 0.15 | 1.19 | 10.36 | 51.16 | 100.88 | 251.30 | 500.43 | 1000.56 | 2001.42 | 3001.01 | 2.00 |
| x25519 | resumption | mls-tls | 1.45 | 2.37 | 11.66 | 52.07 | 103.32 | 253.90 | 503.70 | 1004.97 | 2003.83 | 3006.59 | 2.00 |
| x25519 | resumption-0rtt | openssl | 0.57 | 1.55 | 10.98 | 52.06 | 101.67 | 252.34 | 501.90 | 1003.36 | 2001.26 | 3001.90 | 2.00 |
| x25519 | resumption-1rtt | openssl | 0.51 | 2.59 | 21.98 | 103.74 | 203.22 | 501.62 | 1002.84 | 2003.90 | 4003.83 | 6005.15 | 4.00 |

## mls-tls native (rustcrypto backend, incl. X-Wing post-quantum)

Built with the default `rustcrypto` backend (pure-Rust; the `xwing` suite is the ML-KEM-1024 + P-384 hybrid, unavailable under OpenSSL). request 39 B, response 40 B.

| suite | scenario | stack | 0ms | 1ms | 10ms | 50ms | 100ms | 250ms | 500ms | 1000ms | 2000ms | 3000ms | flights |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p384 | handshake | mls-tls | 9.24 | 11.14 | 30.97 | 110.78 | 211.87 | 524.24 | 1023.07 | 2023.58 | 4026.26 | 6029.77 | 4.01 |
| p384 | key-update | mls-tls | 7.75 | 8.67 | 17.86 | 58.12 | 109.04 | 262.10 | 512.69 | 1012.81 | 2016.94 | 3012.70 | 2.00 |
| p384 | resumption | mls-tls | 7.48 | 8.28 | 18.10 | 58.39 | 108.05 | 265.46 | 511.98 | 1015.32 | 2012.23 | 3009.72 | 2.00 |
| x25519 | handshake | mls-tls | 0.85 | 3.10 | 22.15 | 104.47 | 203.65 | 504.42 | 1005.65 | 2006.37 | 4006.60 | 6005.72 | 4.00 |
| x25519 | key-update | mls-tls | 0.64 | 1.76 | 10.99 | 51.42 | 101.94 | 252.47 | 502.54 | 1002.46 | 2003.17 | 3003.11 | 2.00 |
| x25519 | resumption | mls-tls | 0.69 | 1.76 | 11.10 | 50.94 | 102.60 | 252.43 | 502.33 | 1002.19 | 2002.76 | 3002.40 | 2.00 |
| xwing | handshake | mls-tls | 9.74 | 11.77 | 31.89 | 114.99 | 222.25 | 526.58 | 1026.53 | 2023.66 | 4028.88 | 6029.80 | 4.01 |
| xwing | key-update | mls-tls | 8.45 | 9.48 | 18.81 | 58.95 | 109.44 | 265.06 | 515.15 | 1018.82 | 2012.12 | 3018.25 | 2.01 |
| xwing | resumption | mls-tls | 8.49 | 9.47 | 19.02 | 59.43 | 109.57 | 262.30 | 516.36 | 1015.63 | 2012.76 | 3016.11 | 2.01 |
