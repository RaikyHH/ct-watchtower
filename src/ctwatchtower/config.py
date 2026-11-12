"""Configuration from environment variables (§18.1).

Every value has a default that runs without a `.env` and does nothing outbound:
enrichment off, alerting off, scan trigger off.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Storage
    database_path: Path = REPO_ROOT / "ctwatchtower.sqlite3"
    retention_days: int = 90

    # Ingest (mode A: our own certstream-server-go)
    certstream_url: str = "ws://127.0.0.1:8080/domains-only"
    # Generic, no contact or identity: a deliberate choice.
    ct_user_agent: str = "CT-Watchtower"
    ingest_queue_size: int = 10_000

    # Alerting (§8). Two conditions, not one: switch AND target. That way nothing goes
    # out by accident, and the system screen can say which of the two is missing.
    notify_enabled: bool = False
    notify_webhook_url: str = ""
    notify_secret: str = ""  # set -> HMAC-SHA256 in the X-Watchtower-Signature header
    notify_min_severity: str = "warning"
    notify_window: float = 300.0  # aggregation window in seconds (§8.2.1)
    notify_max_per_hour: int = 12  # §8.2.2
    notify_renotify_days: int = 7  # §8.2.3
    notify_timeout: float = 10.0

    # -- Mail (§8.1) ---------------------------------------------------------
    # A second channel next to the webhook, with the same brakes.
    #
    # Two routes, because one of them often does not work: many networks block the
    # SMTP ports 25, 465 and 587, on home lines almost always. Then `http` over the
    # provider's HTTPS interface, port 443 is open everywhere.
    mail_enabled: bool = False
    mail_transport: str = "smtp"  # smtp | http
    mail_from: str = ""
    mail_to: str = ""  # several separated by commas

    # Route 1: your own or a rented mail server (Hetzner, mailbox.org, Exchange ...)
    mail_smtp_host: str = ""
    mail_smtp_port: int = 587
    mail_smtp_security: str = "starttls"  # starttls | ssl | none
    mail_smtp_user: str = ""
    mail_smtp_password: str = ""

    # Route 2: a provider's HTTPS interface, when the SMTP port is blocked.
    # Which ones exist is in `notify/mail.py`; the key comes from the provider.
    mail_http_provider: str = ""  # brevo | mailgun | mailgun_eu | postmark | resend | sendgrid
    mail_http_key: str = ""
    mail_http_domain: str = ""  # Mailgun only: the sender domain registered there

    # Feeds (§10.2, §11, §18.1)
    indicator_ttl_days: int = 90  # `valid_until` per indicator
    ui_base_url: str = ""  # for links in feeds and alerts, e.g. https://watchtower.internal

    # Language of the abuse template (`config/abuse_templates/<language>.txt`). An
    # unknown value falls back to `en.txt` instead of stopping with an error.
    abuse_language: str = "en"

    # Dedupe (§3.4, §4.4)
    dedupe_cert_ttl: int = 21_600  # 6 h, certificate by SHA-256
    dedupe_finding_ttl: int = 86_400  # 24 h, (tenant_id, registrable)
    rescore_delta: int = 15

    # Enrichment (§7, §18.1, §16). Passive: RDAP/WHOIS at the registry, DNS over DoH -
    # never any contact with the suspicious domain itself. Off by default: registries and
    # resolvers forbid bulk automated queries in their terms of use.
    enrich_enabled: bool = False

    # Enrichment without a click, from the tenant's `thresholds.enrich_from` upwards. Its
    # own switch, and it stays off.
    #
    # Without it campaigns stay empty: they group by registrar, nameserver and
    # network, all enriched data.
    #
    # Its own switch because `enrich_from` sits in every ruleset, old ones included.
    # If the threshold just took effect, an existing installation would start
    # querying by itself on the next restart. See 2026-09-19.
    enrich_auto: bool = False
    enrich_rdap_enabled: bool = True
    enrich_rdap_rps: float = 1.0  # per RDAP/WHOIS server
    # Port 43 has the strictest terms throughout (EURid: no extraction), so off.
    enrich_whois_fallback: bool = False
    # Hard daily caps on top of the rates (UTC day, survives restarts).
    enrich_rdap_daily: int = 200
    enrich_rdap_daily_per_server: int = 50
    enrich_whois_daily: int = 20
    enrich_whois_daily_per_server: int = 10
    enrich_doh_daily: int = 2_000
    enrich_doh_enabled: bool = True
    enrich_doh_primary: str = "https://dns.google/resolve"
    enrich_doh_fallback: str = "https://cloudflare-dns.com/dns-query"
    enrich_doh_rps: float = 10.0
    enrich_timeout: float = 10.0
    # Active modules (§7.6) do not exist; the switch stays off and documents that.
    enrich_active_enabled: bool = False
    # Empty = VirusTotal as a deeplink only (§7.7). An API call is not built.
    vt_api_key: str | None = None

    # Trigger an analysis at an external scanner. The only action in the program where
    # somebody actually visits the suspicious page; the service does it, not us, but
    # this application set it off. So off until somebody switches it on explicitly,
    # and only for a single finding, at the push of a button.
    scan_enabled: bool = False

    # -- Revoked CA certificates (OneCRL) ------------------------------------
    # Mozilla's revocation list, the same one Firefox uses. One fetch a day against
    # infrastructure millions of browsers pull from, and with an ETag, so the normal
    # case is a 304 with no payload.
    revocation_enabled: bool = False
    revocation_interval_hours: int = 24
    # `private` tells the site operator nothing. `public` shows them within minutes
    # that they were spotted, and the site is gone before the abuse report arrives.
    # Whoever wants `public` sets it deliberately.
    scan_visibility: str = "private"
    scan_daily: int = 25  # per service, UTC day, survives restarts
    urlscan_api_key: str | None = None
    scanmalware_api_key: str | None = None

    log_level: str = "INFO"

    # Optional bearer token for /api/v1 (§10, §18.1). Empty = off.
    api_token: str | None = None

    @property
    def psl_path(self) -> Path:
        return DATA_DIR / "public_suffix_list.dat"

    @property
    def confusables_path(self) -> Path:
        return DATA_DIR / "confusables.txt"

    @property
    def parking_path(self) -> Path:
        return DATA_DIR / "parking.yaml"

    @property
    def deeplinks_path(self) -> Path:
        return REPO_ROOT / "config" / "deeplinks.yaml"


settings = Settings()
