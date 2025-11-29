from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import base64
import logging
import requests
import jwt
import os
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from .db.database import Database
from .functions.image_functions import ImageFunctions

logger = logging.getLogger(__name__)
router = APIRouter()
imgf = ImageFunctions()


def verify_jwt_token(request: Request) -> str:
    auth_token = request.cookies.get("authToken")

    if not auth_token:
        logger.warning("No auth token in cookies")
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        secret_key = os.getenv("JWT_SECRET_KEY")
        payload = jwt.decode(auth_token, secret_key, algorithms=["HS256"])
        user_id = payload.get("user_id")

        if not user_id:
            logger.warning("No user_id in token payload")
            raise HTTPException(status_code=401, detail="Invalid token")

        return user_id
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/health")
async def health_check():
    logger.log(msg='Working Fine!', level=1)
    return JSONResponse(
        content={"status": "healthy", "service": "Unmarble API"},
        status_code=200
    )

@router.post("/get_user")
async def get_user(user_id: str = Depends(verify_jwt_token)):
    try:
        with Database() as db:
            user_info = db.get_user_info(user_id)

        return JSONResponse(
            content={
                "user_info": user_info,
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"get_user | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/get_previews")
async def get_previews(user_id: str = Depends(verify_jwt_token)):
    try:
        with Database() as db:
            preview_image_data = db.get_preview_images(user_id)
            preview_design_data = db.get_preview_designs(user_id)

        # Combine into unified structure with 'design' category
        preview_image_data["design"] = preview_design_data

        return JSONResponse(
            content={
                "image_previews": preview_image_data
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"get_previews | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/get_image")
async def get_image(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            image_bytes = db.get_image(
                user_id,
                image_id
                )
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

        return JSONResponse(
            content={
                "image_base64": image_base64,
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"get_image | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/get_design")
async def get_design(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            image_bytes = db.get_design(
                user_id,
                image_id
                )
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

        return JSONResponse(
            content={
                "image_base64": image_base64,
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"get_design | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/upload_image")
async def upload_image(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        category = data.get("category")
        image_base64 = data.get("imageBase64")

        decoded_bytes = base64.b64decode(image_base64)

        max_size_bytes = 6 * 1024 * 1024
        if len(decoded_bytes) > max_size_bytes:
            raise HTTPException(
                status_code=400,
                detail="Image file size exceeds 5MB limit"
            )

        preview_bytes = imgf.create_preview(image_bytes=decoded_bytes)

        with Database() as db:
            result = db.insert_image(
                user_id,
                category,
                decoded_bytes,
                preview_bytes
                )

        return JSONResponse(
            content={
                "image_id": result["image_id"],
                "preview_base64": result["preview_base64"],
                "created_at": result["created_at"],
                "storage_left": result["storage_left"]
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"upload_image | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        if "Insufficient storage space" in str(e):
            raise HTTPException(
                status_code=403,
                detail="Insufficient storage space. Please upgrade to premium for more storage."
            )
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/delete_image")
async def delete_image(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            result = db.delete_image(
                user_id,
                image_id
                )

        if result:
            return JSONResponse(
                content={
                    "success": True,
                    "storage_left": result["storage_left"]
                },
                status_code=200,
            )
        else:
            return JSONResponse(
                content={"success": False},
                status_code=404,
            )
    except Exception as e:
        logger.error(f"delete_image | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/delete_design")
async def delete_design(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            result = db.delete_design(
                user_id,
                image_id
                )

        if result:
            return JSONResponse(
                content={
                    "success": True,
                    "storage_left": result["storage_left"]
                },
                status_code=200,
            )
        else:
            return JSONResponse(
                content={"success": False},
                status_code=404,
            )
    except Exception as e:
        logger.error(f"delete_design | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/design_image")
async def design_image(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        yourself_image_id = data.get("yourself_image_id")
        clothing_image_id = data.get("clothing_image_id")
        category = data.get("category")

        with Database() as db:
            if category == "design":
                yourself_image_bytes = bytes(db.get_design(
                    user_id,
                    yourself_image_id
                    ))
            else:
                yourself_image_bytes = bytes(db.get_image(
                    user_id,
                    yourself_image_id
                    ))
            clothing_image_bytes = bytes(db.get_image(
                user_id,
                clothing_image_id
                ))

        designed_image_bytes = imgf.design_image(
            yourself_image_bytes,
            clothing_image_bytes
            )
        image_base64 = base64.b64encode(designed_image_bytes).decode('utf-8')

        designed_preview_bytes = imgf.create_preview(designed_image_bytes)
        with Database() as db:
            result = db.insert_designed_image(
                user_id,
                yourself_image_id,
                clothing_image_id,
                designed_image_bytes,
                designed_preview_bytes
                )

        return JSONResponse(
            content={
                "image_id": result["image_id"],
                "image_base64": image_base64,
                "preview_base64": result["preview_base64"],
                "created_at": result["created_at"],
                "designs_left": result["designs_left"],
                "storage_left": result["storage_left"]
            },
            status_code=200,
        )
    except Exception as e:
        logger.error(f"design_image | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)

        # Check for content safety violations
        if "CONTENT_SAFETY_VIOLATION" in str(e):
            # Increment NSFW violation counter
            with Database() as db:
                violation_count = db.increment_nsfw_violation(user_id)

            logger.warning(f"Content safety violation detected | {user_id} | violation count: {violation_count} | yourself_image_id: {yourself_image_id} | clothing_image_id: {clothing_image_id}")

            # Construct error message based on violation count
            if violation_count >= 3:
                error_detail = f"CRITICAL: Content Safety Violation (Strike {violation_count}/3) - Your account is under review for repeated safety violations. The uploaded images or generated content violate our safety policies. Further violations will result in permanent account suspension."
            elif violation_count == 2:
                error_detail = f"WARNING: Content Safety Violation (Strike {violation_count}/3) - This is your second violation. The uploaded images or generated content violate our safety policies. One more violation will result in account suspension."
            else:
                error_detail = f"Content Safety Violation (Strike {violation_count}/3) - The uploaded images or generated content violate our safety policies. Please ensure all images are appropriate and comply with our Terms of Service. Repeated violations may result in account suspension."

            raise HTTPException(
                status_code=403,
                detail=error_detail
            )

        if "Insufficient design credits" in str(e):
            raise HTTPException(
                status_code=403,
                detail="Insufficient design credits. Please upgrade to premium for more designs."
            )
        if "Insufficient storage space" in str(e):
            raise HTTPException(
                status_code=403,
                detail="Insufficient storage space. Please upgrade to premium for more storage."
            )
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update_design_fav")
async def update_design_fav(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            result = db.update_design_fav(
                user_id,
                image_id
                )

        return JSONResponse(
            content={"success": result},
            status_code=200,
        )
    except Exception as e:
        logger.error(f"update_design_fav | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update_image_fav")
async def update_image_fav(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        image_id = data.get("image_id")

        with Database() as db:
            result = db.update_image_fav(
                user_id,
                image_id
                )

        return JSONResponse(
            content={"success": result},
            status_code=200,
        )
    except Exception as e:
        logger.error(f"update_image_fav | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/submit_feedback")
async def submit_feedback(request: Request, user_id: str = Depends(verify_jwt_token)):
    try:
        data = await request.json()
        message = data.get("message")

        if not message or len(message.strip()) == 0:
            raise HTTPException(status_code=400, detail="Feedback message cannot be empty")

        if len(message) > 150:
            raise HTTPException(status_code=400, detail="Feedback message cannot exceed 150 characters")

        with Database() as db:
            result = db.insert_feedback(user_id, message.strip())

        return JSONResponse(
            content={
                "feedback_id": result["feedback_id"],
                "created_at": result["created_at"],
                "message": "Feedback submitted successfully"
            },
            status_code=200,
        )
    
    except Exception as e:
        logger.error(f"update_image_fav | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auth/google")
async def google_auth(request: Request):
    try:
        data = await request.json()
        code = data.get("code")

        if not code:
            logger.error(f"Authentication error, could not got the code.")
            raise HTTPException(status_code=400, detail="Authorization code is required")

        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "postmessage")

        google_token_response = await exchange_code_with_google(code, client_id, client_secret, redirect_uri)

        user_info = decode_google_id_token(google_token_response["id_token"], client_id)

        with Database() as db:
            user = db.get_user_by_email(user_info["email"])

            if not user:
                user_id = db.create_google_user(
                    email=user_info.get("email"),
                    name=user_info.get("given_name"),
                    surname=user_info.get("family_name"),
                    picture_url=user_info.get("picture"),
                    google_id=user_info.get("google_id")
                )
            else:
                user_id = user["user_id"]

        auth_token = generate_jwt_token(user_id)

        return JSONResponse(
            content={
                "token": auth_token,
                "user": user_info
            },
            status_code=200
        )
    
    except Exception as e:
        logger.error(f"auth | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

async def exchange_code_with_google(code: str, client_id: str, client_secret: str, redirect_uri: str):
    token_url = "https://oauth2.googleapis.com/token"

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    response = requests.post(token_url, data=payload)

    if response.status_code != 200:
        logger.error(f"Auth, google code exchange")
        raise Exception(f"Failed to exchange code: {response.json()}")

    return response.json()

def decode_google_id_token(token: str, client_id: str):
    try:
        id_info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            client_id
        )

        return {
            "email": id_info.get("email"),
            "name": id_info.get("name", ""),
            "given_name": id_info.get("given_name", ""),
            "family_name": id_info.get("family_name", ""),
            "picture": id_info.get("picture", ""),
            "google_id": id_info.get("sub")
        }
    except ValueError as e:
        logger.error(f"Auth, decode google id token")
        raise Exception(f"Invalid token: {str(e)}")

def generate_jwt_token(user_id: str):
    secret_key = os.getenv("JWT_SECRET_KEY")
    expires_in_days = int(os.getenv("JWT_EXPIRATION_DAYS", 30))
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=expires_in_days),
        "iat": datetime.now(timezone.utc)
    }

    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

@router.post("/webhooks/create_subscription")
async def create_subscription_webhook(request: Request):
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        # Signature verification
        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("create_subscription_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("create_subscription_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("create_subscription_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Check event type
        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_created":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        # Extract subscription data
        data = payload.get("data", {}).get("attributes", {})
        customer_id = data.get("customer_id")
        customer_email = data.get("user_email")
        urls = data.get("urls", {})
        receipt_url = urls.get("receipt")

        if not customer_email:
            logger.error("create_subscription_webhook | Missing user_email in payload")
            raise HTTPException(status_code=400, detail="Missing user_email")

        # Update user subscription
        with Database() as db:
            result = db.update_premium(
                user_email=customer_email,
                customer_id=customer_id,
                receipt_url=receipt_url
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Subscription created successfully",
                "user_id": result["user_id"],
                "user_type": result["user_type"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"create_subscription_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))