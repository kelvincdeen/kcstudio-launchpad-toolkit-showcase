import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware

from helpers import get_current_user, get_admin_access, setup_logger, limiter, AuthInfo, get_client_ip

load_dotenv()
app = FastAPI(root_path="/v1/app")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
logger = setup_logger("app", f"../logs/app/output.log")

@app.get("/health")
def health(): return {"status": "app is healthy"}

@app.get("/public-info")
@limiter.limit("20/minute")
def get_public_info(request: Request):
    logger.info(f"Public info requested by {get_client_ip(request)}")
    return {"message": "This is a public endpoint, anyone can see this."}

@app.get("/user/secret-data")
@limiter.limit("20/minute")
async def read_user_secret_data(request: Request, current_user: AuthInfo = Depends(get_current_user)):
    logger.info(f"User-specific secret data requested for user_id {current_user.user_id}")
    return {"user_id": current_user.user_id, "email": current_user.email, "secret": "The secret ingredient is friendship."}

@app.get("/admin/system-status")
@limiter.limit("5/minute")
async def read_admin_dashboard(request: Request, _=Depends(get_admin_access)):
    logger.warning(f"Admin system status accessed by {get_client_ip(request)}")
    return {"message": "Welcome, Admin! System status: All systems nominal."}
