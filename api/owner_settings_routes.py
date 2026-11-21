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
    # The browser no longer needs to receive the persisted absolute path.  An
    # empty value means "keep the currently configured backend key".
    private_key_path: str = Field(default="", max_length=2048)
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
        values = payload.model_dump()
        if not values["private_key_path"]:
            values["private_key_path"] = owner_settings.current().get(
                owner_settings.FIELDS["private_key_path"], ""
            )
        values = owner_settings.validate(values)
        result = owner_settings.test_connection(values)
        return values, result
    except owner_settings.SettingsValidationError as error:
        raise HTTPException(status_code=422, detail={"message": str(error), "fields": error.errors}) from error


@router.post("/test")
def test_settings(payload: OwnerSettingsRequest, request: Request):
    _administrator(request)
    _, result = _verified(payload)
    return result


@router.post("/private-key")
async def upload_private_key(request: Request):
    """Accept a raw .pem upload and return only its server-side reference."""
    _administrator(request)
    content_length = request.headers.get("content-length")
    try:
        if content_length is not None and int(content_length) > owner_settings.MAX_PRIVATE_KEY_BYTES:
            raise HTTPException(status_code=413, detail="Private key file is too large.")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid upload size.") from None
    content = await request.body()
    if len(content) > owner_settings.MAX_PRIVATE_KEY_BYTES:
        raise HTTPException(status_code=413, detail="Private key file is too large.")
    try:
        path, filename = owner_settings.store_private_key(
            request.headers.get("x-private-key-filename", ""), content
        )
    except owner_settings.SettingsValidationError as error:
        raise HTTPException(status_code=422, detail={"message": str(error), "fields": error.errors}) from error
    return {"private_key_path": path, "filename": filename, "message": "Private key uploaded to the Backend."}


@router.post("")
def save_settings(payload: OwnerSettingsRequest, request: Request):
    actor_id = _administrator(request)
    values, _ = _verified(payload)
    try:
        return owner_settings.save(values, actor_id)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail="Insufficient permissions") from error
