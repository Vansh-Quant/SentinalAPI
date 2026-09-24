"""Shared response models (errors)."""

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    detail: str
