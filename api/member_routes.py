from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from repository import membership

router = APIRouter(prefix="/api/repositories", tags=["Repository members"])


class MemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: int = Field(gt=0, le=9223372036854775807, strict=True)


class LeaveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


@router.get("/{repository_id}/members")
def list_members(repository_id: int, request: Request):
    return {"members": membership.members(request.state.user["id"], repository_id)}


@router.get("/{repository_id}/member-candidates")
def find_candidates(repository_id: int, request: Request, q: str = ""):
    return {"users": membership.candidates(request.state.user["id"], repository_id, q)}


@router.post("/{repository_id}/members")
def add_member(repository_id: int, payload: MemberRequest, request: Request):
    membership.change(request.state.user["id"], repository_id, payload.user_id)
    return {"message": "Member added"}


@router.delete("/{repository_id}/members/{user_id}")
def remove_member(repository_id: int, user_id: int, request: Request):
    membership.change(request.state.user["id"], repository_id, user_id, remove=True)
    return {"message": "Member removed"}


@router.post("/{repository_id}/leave")
def leave_repository(repository_id: int, request: Request, payload: LeaveRequest | None = None):
    membership.change(request.state.user["id"], repository_id, leave=True)
    return {"message": "You left the repository"}
