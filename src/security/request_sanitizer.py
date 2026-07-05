import re
from hashlib import sha256
from typing import Optional, Tuple

class RequestSanitizer:
<<<<<<< HEAD
    """Validates HTTP requests for smuggling & cache poisoning indicators."""

    _HOP_BY_HOP = {
        b"connection", b"keep-alive", b"proxy-authenticate",
        b"proxy-authorization", b"te", b"trailers",
        b"transfer-encoding", b"upgrade",
    }

    @staticmethod
    def _has_control_bytes(value: bytes) -> bool:
        return any(token in value for token in (b"\r", b"\n", b"\x00"))

=======
>>>>>>> 9316945 (Fix HTTP Desync vulnerability by strictly validating CL and TE headers)
    def validate(self, headers: dict) -> Tuple[bool, Optional[str]]:
        has_cl = False
        has_te = False

        for key, value in headers.items():
<<<<<<< HEAD
            if self._has_control_bytes(key):
                return False, "HTTP 400: Invalid header name: control characters"
            if self._has_control_bytes(value):
                return False, (
                    "HTTP 400: Invalid header value: "
                    f"'{key.decode(errors='replace')}'"
                )
            if key.lower() == b"content-length":
                cl = value.strip()
=======
            kl = key.lower()
            if kl == b"content-length":
                has_cl = True
                cl_vals = [v.strip() for v in value.split(b",")]
                if len(set(cl_vals)) > 1:
                    return False, "HTTP 400: Conflicting Content-Length values"
                cl = cl_vals[0]
>>>>>>> 9316945 (Fix HTTP Desync vulnerability by strictly validating CL and TE headers)
                if not cl.isdigit():
                    return False, "HTTP 400: Content-Length not numeric"
                if len(cl) > 1 and cl.startswith(b"0"):
                    return False, "HTTP 400: Content-Length has leading zeros"
                if int(cl) < 0:
                    return False, "HTTP 400: Content-Length negative"
            elif kl == b"transfer-encoding":
                has_te = True
                tv = value.strip().lower()
                if tv in {b"", b"identity"}:
                    return False, "HTTP 400: Invalid Transfer-Encoding"

        if has_cl and has_te:
            return False, "HTTP 400: CL/TE conflict (RFC 7230 §3.3.3)"

        singles = {b"content-length", b"content-type", b"host", b"transfer-encoding"}
        seen = set()
        for key in headers:
            kl = key.lower()
            if kl in singles:
                if kl in seen:
                    return False, f"HTTP 400: Duplicate header: '{key.decode(errors='replace')}'"
                seen.add(kl)

        for key in headers:
            if not re.match(rb"^[a-zA-Z0-9!#$%%&'*+.^_`|~-]+$", key):
                return False, f"HTTP 400: Invalid header name: '{key.decode(errors='replace')}'"

        return True, None

    def cache_key(self, headers: dict) -> str:
<<<<<<< HEAD
        """
        Build a deterministic cache key.

        Strips hop-by-hop headers (RFC 7230 §6.1) and normalizes
        key ordering to prevent cache poisoning via header manipulation.
        """
        sanitized = self.sanitize_headers(headers)
=======
        hop_by_hop = {
            b"connection", b"keep-alive", b"proxy-authenticate",
            b"proxy-authorization", b"te", b"trailers",
            b"transfer-encoding", b"upgrade",
        }
>>>>>>> 9316945 (Fix HTTP Desync vulnerability by strictly validating CL and TE headers)
        normalized = {
            k.decode(errors="replace"): v.decode(errors="replace")
            for k, v in sorted(sanitized.items(), key=lambda kv: kv[0].lower())
        }
        payload = repr(sorted(normalized.items())).encode()
        return sha256(payload).hexdigest()

    def sanitize_headers(self, headers: dict) -> dict:
        """
        Return a forwarding-safe header mapping.

        Invalid inputs are rejected instead of being normalized into a
        request that could be split or smuggled downstream.
        """
        ok, err = self.validate(headers)
        if not ok:
            raise ValueError(err or "HTTP 400: Invalid headers")

        return {
            key.lower(): value
            for key, value in headers.items()
            if key.lower() not in self._HOP_BY_HOP
        }
