# rsotp - The Rust One-Time Password Library

rsotp is a Rust library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods in anywhere that requires users to log in.

Open MFA standards are defined in [RFC 4226][RFC 4226] (HOTP: An HMAC-Based One-Time Password Algorithm) and in [RFC 6238][RFC 6238] (TOTP: Time-Based One-Time Password Algorithm). rsotp implements server-side support for both of these standards.

rsotp was inspired by [PyOTP][PyOTP].


[RFC 4226]: https://tools.ietf.org/html/rfc4226 "RFC 4226"
[RFC 6238]: https://tools.ietf.org/html/rfc6238 "RFC 6238"
[PyOTP]: https://github.com/pyotp/pyotp
