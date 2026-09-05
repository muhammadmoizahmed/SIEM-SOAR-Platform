"""Phase 23 — Threat Intelligence API."""
from fastapi import APIRouter, Depends, Query
from services.threat_intel import (
    lookup_ip_threat_intel, lookup_geo, check_hash,
    check_url, get_all_iocs, enrich_ip,
)
from services.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


@router.get("/ip/{ip}")
def ip_lookup(
    ip: str,
    current_user: User = Depends(get_current_user),
):
    return enrich_ip(ip)


@router.get("/hash/{hash_value}")
def hash_lookup(
    hash_value: str,
    current_user: User = Depends(get_current_user),
):
    result = check_hash(hash_value)
    if result:
        return {"hash": hash_value, "status": "found", "data": result}
    return {"hash": hash_value, "status": "not_found"}


@router.get("/url")
def url_lookup(
    url: str = Query(...),
    current_user: User = Depends(get_current_user),
):
    result = check_url(url)
    if result:
        return {"url": url, "status": "found", "data": result}
    return {"url": url, "status": "clean"}


@router.get("/iocs")
def ioc_summary(
    current_user: User = Depends(get_current_user),
):
    return get_all_iocs()
