"""Built-in SIEM adapters. An adapter is anything with `name`, `configured()`, `target()` and
`send(doc) -> (ok, status_code, error)`. HTTP adapters only need to implement `build(doc)`."""

from datetime import datetime
from urllib.parse import urlparse

import httpx

from app.core.config import Settings
from sentinelforge.registry import registry


def redact_url(url: str) -> str:
    """Show where we send data without leaking userinfo or query-string tokens."""
    if not url:
        return ""
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname or ''}{port}{p.path}"


class HttpAdapter:
    name = "http"
    verify_tls = True

    def __init__(self, settings: Settings):
        self.s = settings

    def configured(self) -> bool:
        raise NotImplementedError

    def target(self) -> str:
        raise NotImplementedError

    def build(self, doc: dict) -> tuple[str, dict, dict]:
        raise NotImplementedError

    def send(self, doc: dict) -> tuple[bool, int | None, str | None]:
        url, headers, body = self.build(doc)
        try:
            with httpx.Client(timeout=self.s.siem_timeout_seconds, verify=self.verify_tls, follow_redirects=False) as c:
                r = c.post(url, headers=headers, json=body)
            return (200 <= r.status_code < 300), r.status_code, None if r.status_code < 300 else r.text[:300]
        except httpx.HTTPError as e:
            return False, None, f"{type(e).__name__}: {e}"[:300]


class WebhookAdapter(HttpAdapter):
    """Generic JSON webhook: POSTs the sentinelforge.detection.v1 document as-is."""

    name = "webhook"

    def configured(self) -> bool:
        return bool(self.s.webhook_url)

    def target(self) -> str:
        return redact_url(self.s.webhook_url)

    def build(self, doc: dict) -> tuple[str, dict, dict]:
        headers = {"Content-Type": "application/json", "User-Agent": "SentinelForge"}
        if self.s.webhook_auth_header:
            headers["Authorization"] = self.s.webhook_auth_header.get_secret_value()
        return self.s.webhook_url, headers, doc


def _epoch(ts: str | None) -> float | None:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class SplunkHecAdapter(HttpAdapter):
    """Splunk HTTP Event Collector. SPLUNK_HEC_URL is the full endpoint, e.g.
    https://splunk.example:8088/services/collector/event"""

    name = "splunk"

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.verify_tls = settings.splunk_verify_tls

    def configured(self) -> bool:
        return bool(self.s.splunk_hec_url and self.s.splunk_hec_token and self.s.splunk_hec_token.get_secret_value())

    def target(self) -> str:
        return redact_url(self.s.splunk_hec_url)

    def build(self, doc: dict) -> tuple[str, dict, dict]:
        body = {"event": doc, "sourcetype": "sentinelforge:detection", "source": self.s.splunk_source,
                "host": doc.get("host", "sentinelforge")}
        if (t := _epoch(doc.get("timestamp"))) is not None:
            body["time"] = t
        if self.s.splunk_index:
            body["index"] = self.s.splunk_index
        token = self.s.splunk_hec_token.get_secret_value() if self.s.splunk_hec_token else ""
        return self.s.splunk_hec_url, {"Authorization": f"Splunk {token}"}, body


class ElasticAdapter(HttpAdapter):
    """Elasticsearch / OpenSearch index API: POST {ELASTIC_URL}/{ELASTIC_INDEX}/_doc"""

    name = "elastic"

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.verify_tls = settings.elastic_verify_tls

    def configured(self) -> bool:
        return bool(self.s.elastic_url)

    def target(self) -> str:
        return f"{redact_url(self.s.elastic_url).rstrip('/')}/{self.s.elastic_index}/_doc"

    def build(self, doc: dict) -> tuple[str, dict, dict]:
        headers = {"Content-Type": "application/json"}
        if self.s.elastic_api_key and self.s.elastic_api_key.get_secret_value():
            headers["Authorization"] = f"ApiKey {self.s.elastic_api_key.get_secret_value()}"
        body = {"@timestamp": doc.get("timestamp"), **doc}
        return f"{self.s.elastic_url.rstrip('/')}/{self.s.elastic_index}/_doc", headers, body


registry.siem_adapters.update(webhook=WebhookAdapter, splunk=SplunkHecAdapter, elastic=ElasticAdapter)
