"""Super User-only settings. Save always verifies the submitted connection anew."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from repository import owner_settings


router = APIRouter(prefix="/api/owner-settings", tags=["Owner Settings"])


class OwnerSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str = Field(max_length=100)
    app_id: str = Field(max_length=100)
    installation_id: str = Field(max_length=100)
    private_key_path: str = Field(max_length=2048)
    workflow: str = Field(max_length=255)


def _administrator(request):
    user = request.state.user
    if not user or user["role"] != "superuser":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user["id"]


@router.get("")
def get_settings(request: Request):
    _administrator(request)
    return owner_settings.read()


def _verified(payload):
    try:
        values = owner_settings.validate(payload.model_dump())
        result = owner_settings.test_connection(values)
        return values, result
    except owner_settings.SettingsValidationError as error:
        raise HTTPException(status_code=422, detail={"message": str(error), "fields": error.errors}) from error


@router.post("/test")
def test_settings(payload: OwnerSettingsRequest, request: Request):
    _administrator(request)
    _, result = _verified(payload)
    return result


@router.post("")
def save_settings(payload: OwnerSettingsRequest, request: Request):
    actor_id = _administrator(request)
    values, _ = _verified(payload)
    try:
        return owner_settings.save(values, actor_id)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail="Insufficient permissions") from error
