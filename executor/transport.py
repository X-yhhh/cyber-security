"""认证机器协议与本机 mTLS 解析；凭据只从受控文件读取，不跟随重定向。"""
import ipaddress
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .common import Rejected, canonical, ident, parse, private_file, require
from .contract import BINDING_FIELDS


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Rejected("HTTP_REDIRECT_REJECTED")


class HTTPS:
    def __init__(self, base, ca_file=None, cert_file=None, key_file=None, local=False):
        url = urllib.parse.urlsplit(base)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password and
                not url.query and not url.fragment, "HTTPS_REQUIRED")
        if local:
            try:
                require(ipaddress.ip_address(url.hostname).is_loopback, "LOCAL_RESOLVER_REQUIRED")
            except ValueError as exc:
                raise Rejected("LOCAL_RESOLVER_REQUIRED") from exc
        self.base = base.rstrip("/")
        context = ssl.create_default_context(cafile=str(private_file(ca_file)) if ca_file else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if cert_file:
            context.load_cert_chain(str(private_file(cert_file)), str(private_file(key_file)))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=context))

    def post(self, suffix, body, headers=None):
        request = urllib.request.Request(self.base + suffix, data=canonical(body), method="POST",
                                         headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with self.opener.open(request, timeout=.75) as response:
                raw = response.read((1 << 20) + 1)
                require(len(raw) <= 1 << 20, "RESPONSE_TOO_LARGE")
                return parse(raw)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise Rejected("CONTROL_PLANE_UNAVAILABLE") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Rejected("CONTROL_PLANE_UNAVAILABLE") from exc


class ControlPlane:
    def __init__(self, config):
        self.config = config
        c = config()
        self.http = HTTPS(c["controlPlaneURL"], c.get("controlPlaneCA"))

    def post(self, operation, body, request_id=None):
        require(operation in {"heartbeats", "command-claims", "receipts", "reconciliations",
                              "target-bindings", "budget-proofs", "clearance-proofs"}, "INVALID_OPERATION")
        c = self.config()
        token = private_file(c["credentialFile"]).read_text().strip()
        require(token and "\n" not in token and "\r" not in token, "MACHINE_CREDENTIAL_INVALID")
        response = self.http.post("/api/v2/machine/executors/" + c["executorId"] + "/" + operation, body,
                                  {"Authorization": "Bearer " + token, "Idempotency-Key": request_id or ident()})
        require(isinstance(response, dict) and response.get("error") is None and
                isinstance(response.get("data"), dict) and response.get("requestId"), "CONTROL_RESPONSE_INVALID")
        return response["data"]


class TargetResolver:
    def __init__(self, config):
        c = config()
        self.http = HTTPS(c["targetURL"], c["targetCA"], c["targetCertificate"], c["targetKey"], local=True)

    def resolve(self, payload):
        return self.http.post("/v1/targets/resolve-lease", {"targetRef": payload["targetRef"],
                                                    "binding": {k: payload[k] for k in BINDING_FIELDS}})
