from fastapi import APIRouter, Request, HTTPException, Depends, UploadFile, File, Form
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
    

@router.post("/complete_onboarding")
async def complete_onboarding(
    request: Request,
    user_id: str = Depends(verify_jwt_token)
):
    """
    Complete onboarding flow:
    1. Copy default clothing images to user's images table
    2. Decrement storage_left for each copied image
    3. Set user_status to 'onboarded' (ready for tour)

    Request body:
    - gender: string (required) - to filter which defaults to copy

    Returns:
    - success: boolean
    - storage_left: int (new value after copying)
    - copied_images: list of {id, base64, faved, created_at}
    """
    try:
        data = await request.json()
        gender = data.get("gender")

        if not gender:
            raise HTTPException(status_code=400, detail="Gender is required")

        with Database() as db:
            # Copy defaults to user's images
            copy_result = db.copy_defaults_to_user(user_id, gender)

            # Mark onboarding as complete
            db.complete_onboarding(user_id)

        return JSONResponse(
            content={
                "success": True,
                "storage_left": copy_result["storage_left"],
                "copied_images": copy_result["copied_images"]
            },
            status_code=200
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"complete_onboarding | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/complete_tour")
async def complete_tour(user_id: str = Depends(verify_jwt_token)):
    """
    Mark gallery tour as completed.
    Sets user_status to 'active' (fully onboarded).

    This endpoint is called when the user sees the first step of the gallery tour,
    ensuring they don't see the tour again on subsequent visits.

    Returns:
    - success: boolean
    """
    try:
        with Database() as db:
            db.complete_tour(user_id)

        return JSONResponse(
            content={
                "success": True
            },
            status_code=200
        )

    except Exception as e:
        logger.error(f"complete_tour | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/get_default_previews")
async def get_default_previews(
    request: Request,
    user_id: str = Depends(verify_jwt_token)
):
    """Get default clothing previews for onboarding based on gender"""
    try:
        body = await request.json()
        gender = body.get("gender")
        ids = body.get("ids")  # Optional: specific IDs to fetch

        if not gender:
            return JSONResponse(
                content={"error": "Gender required"},
                status_code=400
            )

        with Database() as db:
            previews = db.get_default_previews(gender, ids)

        return JSONResponse(
            content={"previews": previews},
            status_code=200
        )

    except Exception as e:
        logger.error(f"get_default_previews | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/design_onboarding")
async def design_onboarding(
    request: Request,
    user_id: str = Depends(verify_jwt_token)
):
    yourself_image_id = None
    default_clothing_id = None

    try:
        data = await request.json()
        yourself_image_id = data.get("yourself_image_id")
        default_clothing_id = data.get("default_clothing_id")

        if not yourself_image_id or not default_clothing_id:
            raise HTTPException(
                status_code=400,
                detail="Both yourself_image_id and default_clothing_id are required"
            )

        # Get the user's uploaded image
        with Database() as db:
            yourself_image_bytes = bytes(db.get_image(
                user_id,
                yourself_image_id
            ))

            # Get the default clothing image from defaults table
            default_image = db.get_default_image(default_clothing_id)

            if not default_image:
                raise HTTPException(
                    status_code=404,
                    detail="Default clothing image not found"
                )

            clothing_image_id = default_image["image_id"]
            clothing_image_bytes = bytes(default_image["image_bytes"])

        # Generate the design
        designed_image_bytes = imgf.design_image(
            yourself_image_bytes,
            clothing_image_bytes
        )
        image_base64 = base64.b64encode(designed_image_bytes).decode('utf-8')

        # Create preview and save to database
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

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"design_onboarding | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)

        # Check for content safety violations
        if "CONTENT_SAFETY_VIOLATION" in str(e):
            with Database() as db:
                violation_count = db.increment_nsfw_violation(user_id)

            logger.warning(f"Content safety violation detected | {user_id} | violation count: {violation_count} | yourself_image_id: {yourself_image_id} | default_clothing_id: {default_clothing_id}")

            if violation_count >= 3:
                error_detail = f"CRITICAL: Content Safety Violation (Strike {violation_count}/3) - Your account is under review for repeated safety violations."
            elif violation_count == 2:
                error_detail = f"WARNING: Content Safety Violation (Strike {violation_count}/3) - This is your second violation."
            else:
                error_detail = f"Content Safety Violation (Strike {violation_count}/3) - The uploaded images violate our safety policies."

            raise HTTPException(status_code=403, detail=error_detail)

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
async def upload_image(
    file: UploadFile = File(...),
    category: str = Form(...),
    user_id: str = Depends(verify_jwt_token)
):
    try:
        image_bytes = await file.read()

        max_size_bytes = 6 * 1024 * 1024
        if len(image_bytes) > max_size_bytes:
            raise HTTPException(
                status_code=400,
                detail="Image file size exceeds 5MB limit"
            )

        preview_bytes = imgf.create_preview(image_bytes=image_bytes)

        with Database() as db:
            result = db.insert_image(
                user_id,
                category,
                image_bytes,
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


@router.post("/webhooks/subscription_created")
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
        data = payload.get("data", {})
        subscription_id = str(data.get("id", ""))
        attributes = data.get("attributes", {})
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")
        urls = attributes.get("urls", {})
        receipt_url = urls.get("receipt")

        if not customer_email:
            logger.error("create_subscription_webhook | Missing user_email in payload")
            raise HTTPException(status_code=400, detail="Missing user_email")

        # Update user subscription
        with Database() as db:
            result = db.create_subscription(
                user_email=customer_email,
                customer_id=customer_id,
                receipt_url=receipt_url,
                subscription_id=subscription_id
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


@router.post("/webhooks/subscription_cancelled")
async def subscription_cancelled_webhook(request: Request):
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        # Signature verification
        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_cancelled_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_cancelled_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_cancelled_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Check event type
        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_cancelled":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        # Extract subscription data
        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(data.get("id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        # Priority: ends_at > renews_at > calculated from last_payment_at
        ends_at_str = attributes.get("ends_at")
        renews_at_str = attributes.get("renews_at")

        ends_at = None

        if ends_at_str:
            ends_at = datetime.fromisoformat(ends_at_str.replace("Z", "+00:00"))
        elif renews_at_str:
            ends_at = datetime.fromisoformat(renews_at_str.replace("Z", "+00:00"))
        # If both are None, database function will calculate from last_payment_at

        # We need at least customer_id or email to find the user
        if not customer_id and not customer_email:
            logger.error("subscription_cancelled_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        # Update user subscription status
        with Database() as db:
            result = db.cancel_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id,
                ends_at=ends_at
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Subscription cancellation recorded",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"],
                "subscription_ends_at": result["subscription_ends_at"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_cancelled_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_resumed")
async def subscription_resumed_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_resumed event.
    User resumed their cancelled subscription before it expired.
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_resumed_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_resumed_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_resumed_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_resumed":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(data.get("id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_resumed_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.resume_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Subscription resumed successfully",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_resumed_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_expired")
async def subscription_expired_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_expired event.
    User's cancelled subscription has reached its end date.
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_expired_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_expired_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_expired_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_expired":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(data.get("id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_expired_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.expire_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Subscription expired",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_expired_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_payment_success")
async def subscription_payment_success_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_payment_success event.
    Monthly renewal - reset design credits to 50.
    Storage is NOT reset (cumulative).
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_payment_success_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_payment_success_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_payment_success_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_payment_success":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(attributes.get("subscription_id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_payment_success_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.renew_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Subscription renewed successfully",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"],
                "designs_left": result["designs_left"],
                "storage_left": result["storage_left"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_payment_success_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_payment_failed")
async def subscription_payment_failed_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_payment_failed event.
    Payment failed - mark as past_due. User still has access while LS retries.
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_payment_failed_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_payment_failed_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_payment_failed_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_payment_failed":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(attributes.get("subscription_id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_payment_failed_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.fail_subscription_payment(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        logger.warning(f"subscription_payment_failed_webhook | User {customer_email or customer_id} payment failed, marked as past_due")

        return JSONResponse(
            status_code=200,
            content={
                "message": "Payment failure recorded",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_payment_failed_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_payment_recovered")
async def subscription_payment_recovered_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_payment_recovered event.
    Failed payment recovered - restore active status.
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_payment_recovered_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_payment_recovered_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_payment_recovered_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_payment_recovered":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(attributes.get("subscription_id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_payment_recovered_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.recover_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Payment recovered successfully",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_payment_recovered_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhooks/subscription_payment_refunded")
async def subscription_payment_refunded_webhook(request: Request):
    """
    Handle Lemon Squeezy subscription_payment_refunded event.
    Refund issued - revoke access immediately (EU 14-day compliance).
    """
    try:
        body = await request.body()
        payload = await request.json()
        signature = request.headers.get("X-Signature")

        webhook_secret = os.getenv("LEMON_SQUEEZY_SECRET_KEY")

        if not webhook_secret:
            logger.error("subscription_payment_refunded_webhook | LEMON_SQUEEZY_SECRET_KEY not configured")
            raise HTTPException(status_code=500, detail="Webhook secret not configured")

        expected_signature = hmac.new(
            webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()

        if not signature:
            logger.warning("subscription_payment_refunded_webhook | Missing X-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")

        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("subscription_payment_refunded_webhook | Invalid signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        event_name = payload.get("meta", {}).get("event_name")
        if event_name != "subscription_payment_refunded":
            return JSONResponse(
                status_code=200,
                content={"message": f"Event {event_name} ignored"}
            )

        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        subscription_id = str(attributes.get("subscription_id", ""))
        customer_id = attributes.get("customer_id")
        customer_email = attributes.get("user_email")

        if not customer_id and not customer_email:
            logger.error("subscription_payment_refunded_webhook | Missing both customer_id and user_email in payload")
            raise HTTPException(status_code=400, detail="Missing customer identifier")

        with Database() as db:
            result = db.refund_subscription(
                customer_id=customer_id,
                user_email=customer_email,
                subscription_id=subscription_id
            )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Refund processed, access revoked",
                "user_id": result["user_id"],
                "subscription_status": result["subscription_status"]
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"subscription_payment_refunded_webhook | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cancel_subscription")
async def cancel_subscription(request: Request, user_id: str = Depends(verify_jwt_token)):
    """
    User-initiated subscription cancellation.
    Calls Lemon Squeezy API to cancel the subscription.
    """
    try:
        data = await request.json()
        reason = data.get("reason", "")

        with Database() as db:
            user_subscription = db.get_user_subscription_id(user_id)

        if not user_subscription:
            raise HTTPException(status_code=400, detail="No active subscription found")

        subscription_id = user_subscription["subscription_id"]

        if not subscription_id:
            raise HTTPException(status_code=400, detail="No subscription ID found")

        # Call Lemon Squeezy API to cancel subscription
        ls_api_key = os.getenv("LEMON_SQUEEZY_API_KEY")

        if not ls_api_key:
            logger.error("cancel_subscription | LEMON_SQUEEZY_API_KEY not configured")
            raise HTTPException(status_code=500, detail="Payment service not configured")

        response = requests.delete(
            f"https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {ls_api_key}",
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json"
            }
        )

        if response.status_code not in [200, 204]:
            logger.error(f"cancel_subscription | Lemon Squeezy API error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=500, detail="Failed to cancel subscription")

        # Store cancellation reason for analytics (optional)
        if reason:
            with Database() as db:
                db.store_cancellation_reason(user_id, reason)

        return JSONResponse(
            content={"message": "Subscription cancelled successfully"},
            status_code=200
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"cancel_subscription | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/resume_subscription")
async def resume_subscription(user_id: str = Depends(verify_jwt_token)):
    """
    User-initiated subscription resume.
    Resumes a cancelled subscription by calling Lemon Squeezy API.
    Only works if the subscription is in 'cancelled' state (before expiry).
    """
    try:
        with Database() as db:
            user_subscription = db.get_user_subscription_for_resume(user_id)

        if not user_subscription:
            raise HTTPException(status_code=400, detail="No cancelled subscription found to resume")

        subscription_id = user_subscription["subscription_id"]

        if not subscription_id:
            raise HTTPException(status_code=400, detail="No subscription ID found")

        # Call Lemon Squeezy API to resume subscription
        ls_api_key = os.getenv("LEMON_SQUEEZY_API_KEY")

        if not ls_api_key:
            logger.error("resume_subscription | LEMON_SQUEEZY_API_KEY not configured")
            raise HTTPException(status_code=500, detail="Payment service not configured")

        # Resume by setting cancelled to false
        response = requests.patch(
            f"https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {ls_api_key}",
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json"
            },
            json={
                "data": {
                    "type": "subscriptions",
                    "id": str(subscription_id),
                    "attributes": {
                        "cancelled": False
                    }
                }
            }
        )

        if response.status_code != 200:
            logger.error(f"resume_subscription | Lemon Squeezy API error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=500, detail="Failed to resume subscription")

        return JSONResponse(
            content={"message": "Subscription resumed successfully"},
            status_code=200
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"resume_subscription | {user_id} | {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))