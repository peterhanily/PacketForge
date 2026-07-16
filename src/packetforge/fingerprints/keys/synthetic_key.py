# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A throwaway SYNTHETIC signing key for generating fake self-signed certs.

This is NOT a credential. It signs the inert, self-signed X.509 certificates that
PacketForge presents in synthetic TLS handshakes, so captures are byte-deterministic. It
grants access to nothing. Stored as base64(DER) (not PEM) so it is unambiguously a test
fixture and not mistaken for a live key.
"""

_KEY_B64 = (
    "MIIEowIBAAKCAQEAkMRcfKYQbeqkWMhlRRmvFVzDowk6yxEyJytXUcFaJeK6brzlMMpBULob3nfQ"
    "t/6XbpgguWJELETeSXNC8VDF9dx3of0u2aMmuXWKjBt3AfbFInpp0+vITL8fjvJ97YnQEN0QzlJY"
    "LK6YkLfoCXHhifnpiIzJGVmzQVF6OgimtY32BZXp1GwXj06aeqypA24x651Sj79yQQHO4CdWUn3Y"
    "TaAjiPCPhj1SQIDhfZqD3Qgf+JgQRtXfeqRJ9nS9x8VVQ4PDNHwBb4VuHsiRQVrHGrnudXBUSIR3"
    "fBpFzz//5eBab8LLw65OqEnVt+soUpSxYGMeBJ6pzSnnmckf7sVUVQIDAQABAoIBAAFGoCoMRjv+"
    "kJ3XsxmXNSif1xMqYA8Tth8L2r31t+QT/RPZkyUi8ABuI3pXQ/4OWF25KYPfKD3bo+0YMioLGpnx"
    "uRXMZwuz/5tfoqD2Sc45Bo1cCgkigtlqT2gX6wdoHe7ug9kA3ZYUBw3MRFdEK0cablx6h5GZoMk3"
    "Y2rJHyI3SRWFHJKEhXEyFv5P7OQZZLfneiwMFLBw8zfQvCmq8PxXu/08C7IpMDPZEZZLGy52K4ZR"
    "1KNDKapM46oth+HeGHWPyRrmhuosq40G5PbnFNaUMPikn4WWwo9WhkYPdp3+4tpxKgB8HihQimjb"
    "tmvr8i+SBKV9EsKTvhOv5wvK4AECgYEAzHbuFVGmLPqj4P05CvNo8I2MJeZaeo4D4Y/rgrU1Wf9W"
    "52FBOvlPEVmUWp0t0WNx2qxBYPxvMulZ+Cp6Ga+38wOo5bIbGAG8E0/cUB9UVG16IOyMLJWizFwl"
    "TuZER1AhNxyCm6ww1CjlMzDSm2Oh8b6Nkez1IREjTbKX2ylLFwECgYEAtUFzIq5BUyCTPTZOvZvF"
    "x4d3FGg39xz9uTTz28Su2hozGsAiggVyhksO/kuNX4ULG5iuBEH60/xNWU0412s1e5Ns1ISrRrl+"
    "fBhMhi/VRwmwwXbPhFMzJ1vA1mKKUAySFfjT2NiANSop/K2DPavy4NJR58pQEnZ8B10Yp9TvsVUC"
    "gYARTkOqhEWnavNx+JzaY23PZnulPZEM7HZBojfR0VqZqnYFkYK+5hkeI9HdtY4KOfuKAahq+BLF"
    "YWDfE2FQSUItjHLANkn6xzLPA6RnF6/AkZ+Tp9HZeDTWTTpPKkg/LPYSvxQC7xkW6/syUQCSbGVp"
    "m7JJ1p+M0/GEAwi9YQpdAQKBgQCphJ3WyJxlz2iFbj40TPSriMFQ/6uf3KhbR+/uEUPqzWgQU7Oy"
    "YL/cY2SRZj3BIR/jXmcZqk+ZZTU+GN/ZcPYjLh0xoSbCzYdDLkKbmS7h8mkydxjbzChiXgi7OIvd"
    "E/Sowf/3pXw6vMVqASlmS2Oq6mkZ3HgI3HFhPatqg9bsxQKBgHo5A1JwiM4iHx0M0mXVRaInAzRX"
    "5vvbSZpVAjKhgdu6DASozB6ZgUr8gNKXZEnUOfFjyI/C/MDvWlbonkepSpwrSd5VkPrMwu/taLg1"
    "+HyizqG3dGH5srJmc2AGnUlYSe/Bss7febLmmHPLEUFPvQ9qa2BnqJkBNanWkXLXDmk1"
)


def synthetic_key_der() -> bytes:
    import base64
    return base64.b64decode("".join(_KEY_B64.split()))
