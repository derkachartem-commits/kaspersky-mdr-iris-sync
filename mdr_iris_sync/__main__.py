"""Entry point: ``python -m mdr_iris_sync --config config.json``."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .config import load_config
from .iris_client import IrisClient
from .logging_setup import setup_logging
from .mdr_client import MDRClient, MDRTokenStore, TokenKeeper
from .proxy import describe_proxies, proxies_for_url, resolve_proxy_config
from .state import StateDB
from .sync import Syncer


def _verify_value(section_cfg: Dict[str, Any]) -> Any:
    ca_bundle = section_cfg.get("ca_bundle")
    if ca_bundle:
        return ca_bundle
    return bool(section_cfg.get("verify", True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mdr_iris_sync",
        description=(
            "Bidirectional Kaspersky MDR <-> DFIR-IRIS synchronization: "
            "alerts, cases, statuses and comments."
        ),
    )
    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="path to config.json (default: ./config.json)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one synchronization cycle and exit (useful for cron/systemd timers)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="override logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    cfg = load_config(args.config)
    if args.log_level:
        cfg["log"]["level"] = args.log_level
    logger = setup_logging(cfg)

    interval = int(cfg["interval_seconds"])
    logger.info("starting mdr-iris-sync; interval=%ss", interval)

    # Proxy resolution: global settings can be inherited or overridden per service.
    mdr_proxy_cfg = resolve_proxy_config(cfg.get("proxy"), cfg["mdr"].get("proxy"))
    iris_proxy_cfg = resolve_proxy_config(cfg.get("proxy"), cfg["iris"].get("proxy"))
    mdr_proxies = proxies_for_url(mdr_proxy_cfg, cfg["mdr"]["api_url"])
    iris_proxies = proxies_for_url(iris_proxy_cfg, cfg["iris"]["api_url"])
    logger.info("proxy for MDR: %s", describe_proxies(mdr_proxies))
    logger.info("proxy for IRIS: %s", describe_proxies(iris_proxies))

    db = StateDB(cfg["state_db"])
    tokens = MDRTokenStore(
        cfg["mdr"]["tokens_file"],
        api_url=cfg["mdr"]["api_url"],
        client_id=cfg["mdr"]["client_id"],
        refresh_token=cfg["mdr"].get("refresh_token", ""),
        verify=_verify_value(cfg["mdr"]),
        timeout=int(cfg["mdr"].get("timeout", 60)),
        refresh_before_seconds=int(
            cfg["mdr"]["token_refresh"].get("refresh_before_seconds", 180)
        ),
        retry_delay_seconds=int(
            cfg["mdr"]["token_refresh"].get("retry_delay_seconds", 5)
        ),
        max_delay_seconds=int(
            cfg["mdr"]["token_refresh"].get("max_delay_seconds", 300)
        ),
        proxies=mdr_proxies,
        logger=logger,
    )

    mdr = MDRClient(
        api_url=cfg["mdr"]["api_url"],
        client_id=cfg["mdr"]["client_id"],
        tokens=tokens,
        verify=_verify_value(cfg["mdr"]),
        timeout=int(cfg["mdr"].get("timeout", 60)),
        page_size=int(cfg["mdr"].get("page_size", 100)),
        max_pages=int(cfg["mdr"].get("max_pages", 100)),
        proxies=mdr_proxies,
        logger=logger,
    )
    iris = IrisClient(
        api_url=cfg["iris"]["api_url"],
        api_key=cfg["iris"]["api_key"],
        verify=_verify_value(cfg["iris"]),
        timeout=int(cfg["iris"].get("timeout", 60)),
        proxies=iris_proxies,
        logger=logger,
    )

    syncer = Syncer(cfg, db, mdr, iris, logger=logger)

    if args.once:
        stats = syncer.run_cycle()
        db.close()
        logger.info("single cycle finished: %s", stats)
        return 0 if not stats.get("errors") else 1

    stop = threading.Event()
    keeper = TokenKeeper(
        tokens,
        interval_seconds=int(
            cfg["mdr"]["token_refresh"].get("check_interval_seconds", 30)
        ),
    )

    def _handle_signal(signum: int, _frame: Any) -> None:
        logger.info("signal %s received; stopping", signum)
        stop.set()
        keeper.stop()
        tokens.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    keeper.start()
    exit_code = 0
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                syncer.run_cycle()
            except Exception:  # noqa: BLE001
                exit_code = 1
                logger.exception("unexpected error in sync cycle")

            elapsed = time.monotonic() - started
            wait_for = max(1.0, interval - elapsed)
            logger.debug("next cycle in %.1fs", wait_for)
            stop.wait(wait_for)
    except KeyboardInterrupt:
        logger.info("interrupted")
    finally:
        keeper.stop()
        tokens.stop()
        db.close()
        logger.info("mdr-iris-sync stopped")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
