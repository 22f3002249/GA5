from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal

router = APIRouter()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: Literal["v1", "v2"]


class ProrationResponse(BaseModel):
    charge: float


@router.post("/proration", response_model=ProrationResponse)
def proration(req: ProrationRequest):
    if req.spec == "v1":
        divisor = 30.0
    elif req.spec == "v2":
        if req.days_in_actual_month <= 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month must be positive")
        divisor = req.days_in_actual_month
    else:
        # Pydantic's Literal already blocks this, but keep an explicit guard
        raise HTTPException(status_code=400, detail="invalid spec")

    charge = (req.new_price - req.old_price) * (req.days_remaining / divisor)
    return {"charge": charge}
