from fastapi import APIRouter

from modules.api.v1.auth import router as auth_router
from modules.api.v1.users import router as users_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(users_router)
