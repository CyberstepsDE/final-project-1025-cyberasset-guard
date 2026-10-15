"""Application logging: one stderr handler on the `app` logger (all modules use
getLogger(__name__), so they inherit it). Uvicorn keeps its own access/server logs.

Never log request bodies, secrets or full configuration - log identifiers instead.
"""
import logging
import sys

FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_MARKER = "_cag_handler"


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("app")
    logger.setLevel(level)
    if not any(getattr(h, _MARKER, False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(FORMAT))
        setattr(handler, _MARKER, True)
        logger.addHandler(handler)
    logger.propagate = False
    return logger
