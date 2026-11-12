"""Flask app factory. One process: HTTP layer plus pipeline thread.

No login (§1.2). Whoever exposes the app puts a reverse proxy in front of it and
sets `API_TOKEN`. It binds to `127.0.0.1` by default.
"""

from __future__ import annotations

import atexit
import logging
import os
from pathlib import Path

from flask import Flask, jsonify

from ctwatchtower import settings_store
from ctwatchtower.api import bp as api_bp
from ctwatchtower.api.feed import bp as feed_bp
from ctwatchtower.config import settings
from ctwatchtower.db import connect
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RULES_DIR, RuleStore
from ctwatchtower.web import bp as ui_bp

log = logging.getLogger(__name__)


def sync_shipped_rules(rules_dir: Path, shipped: Path | None = None) -> list[str]:
    """Pull the shipped building blocks into the rules directory (`common/`, template).

    In the container `rules/` sits on a volume that hides the image version. Without
    this sync an existing installation is missing every building block that was
    added after its first start, and then every ruleset that includes one fails to
    load. Tenant files stay untouched: those belong to the user, not to the image.
    """
    source = Path(shipped) if shipped else Path(__file__).resolve().parents[2] / "rules-shipped"
    if not source.is_dir():
        return []  # development without a container: `rules/` is the original already
    renewed = []
    for path in [*source.glob("common/*.y*ml"), source / "_template.yaml"]:
        if not path.is_file():
            continue
        target = rules_dir / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        fresh = path.read_bytes()
        if not target.is_file() or target.read_bytes() != fresh:
            target.write_bytes(fresh)
            renewed.append(str(target.relative_to(rules_dir)))
    if renewed:
        log.info("shipped rule building blocks updated: %s", ", ".join(renewed))
    return renewed


def create_app(
    *,
    db_path: str | Path | None = None,
    rules_dir: str | Path | None = None,
    start_pipeline: bool = True,
    certstream_url: str | None = None,
) -> Flask:
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
        static_url_path="/static",
    )
    rules_dir = Path(rules_dir or RULES_DIR)
    sync_shipped_rules(rules_dir)
    conn = connect(db_path)
    # Before the pipeline: it reads from `settings` while being built, so whatever
    # somebody changed through the UI has to be in there by then.
    applied = settings_store.apply_stored(conn)
    if applied:
        log.info("%d settings taken from the database", applied)
    store = RuleStore(rules_dir)
    pipeline = Pipeline(conn, store, url=certstream_url)
    # So the UI can hand the running checker a new list without knowing about the
    # pipeline.
    app.config["REVOCATION"] = pipeline.revocation

    app.config.update(
        DB=conn,
        RULES=store,
        RULES_DIR=rules_dir,
        PIPELINE=pipeline,
        API_TOKEN=settings.api_token or None,  # read on the call, not at import time
    )

    @app.after_request
    def security_headers(response):
        """The UI displays strings an attacker chose: domain names.

        `render_domain` escapes every character; these headers are the second line,
        in case a gap ever opens there. With no inline scripts (the screen starts
        from `body[data-screen]`) and no foreign origins (fonts are local), a strict
        policy without `unsafe-inline` for scripts is enough.
        """
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # No referrer outwards: the URL carries tenant ids and search terms.
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # The server name tells an attacker what to look for and is of no use to
        # anybody else.
        response.headers["Server"] = "CT-Watchtower"
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    app.register_blueprint(api_bp)
    app.register_blueprint(feed_bp)
    app.register_blueprint(ui_bp)

    if start_pipeline:
        pipeline.start()
        atexit.register(pipeline.stop)
    return app


def main() -> None:  # pragma: no cover - development server
    logging.basicConfig(level=settings.log_level)
    app = create_app()
    # threaded=True: SSE holds one thread per connection (§10, agent role).
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)), threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
