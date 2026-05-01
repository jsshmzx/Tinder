from fastapi import APIRouter

from modules.api.v1.auth import router as auth_router

router = APIRouter()
router.include_router(auth_router)
