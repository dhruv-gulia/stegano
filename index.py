"""Vercel entrypoint: Vercel looks for a FastAPI instance named `app` at the repo root."""
from steg.web import app  # noqa: F401
