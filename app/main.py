"""orders-api: the small service Falco protects. Deliberately boring."""
from fastapi import FastAPI

app = FastAPI(title="orders-api")
ORDERS = [{"id": 1, "item": "fibre patch cord", "qty": 3}]


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/orders")
def orders() -> list[dict]:
    return ORDERS
