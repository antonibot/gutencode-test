from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    # read-scope: public — liveness probe, returns only {status}, no domain state.
    return HealthResponse(status="ok")
