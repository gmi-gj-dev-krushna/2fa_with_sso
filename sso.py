from flask import (
    Blueprint,
    jsonify,
    request,
    redirect,
    url_for,
    g,
    make_response,
    render_template,
)
from authlib.integrations.flask_client import OAuth
from authlib.oauth2 import OAuth2Error
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
import jwt
import random
import string
from functools import wraps
from models import db, User, Session, OAuthProvider
from flask_mail import Message
from extensions import mail
from flask import render_template_string
from uuid import uuid4
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

sso_bp = Blueprint("sso", __name__)

oauth = OAuth()
JWT_SECRET = os.getenv("JWT_SECRET", "default_secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_IN = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES_IN = timedelta(days=30)
OTP_EXPIRATION_TIME = timedelta(minutes=5)

# OAuth configurations
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="facebook",
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url="https://graph.facebook.com/oauth/access_token",
    authorize_url="https://www.facebook.com/dialog/oauth",
    api_base_url="https://graph.facebook.com/",
    client_kwargs={"scope": "email"},
)

oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={
        "scope": "read:user user:email",
        "token_endpoint_auth_method": "client_secret_post",
    },
)

oauth.register(
    name="jira",
    client_id=os.getenv("JIRA_CLIENT_ID"),
    client_secret=os.getenv("JIRA_CLIENT_SECRET"),
    access_token_url="https://auth.atlassian.com/oauth/token",
    authorize_url="https://auth.atlassian.com/authorize",
    api_base_url="https://api.atlassian.com/",
    client_kwargs={
        "scope": "read:me read:account",
        "audience": "api.atlassian.com",
        "prompt": "consent",
    },
)


# Helper Functions
def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        session_id = request.cookies.get("session_id")
        if not token or not session_id:
            return redirect("/login")

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user = User.query.get(payload["user_id"])
            if not user:
                raise jwt.InvalidTokenError

            session = Session.query.filter_by(id=session_id, user_id=user.id).first()
            if not session or session.jwt_token != token:
                raise jwt.InvalidTokenError

            if datetime.now(timezone.utc) > session.expires_at:
                raise jwt.ExpiredSignatureError

            g.user = user
            g.session = session
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    return decorated


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


def send_otp_email(email, otp):
    subject = "Secure Login: Your One-Time Password (OTP)"
    html_body = render_template_string(
        """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your One-Time Password</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4CAF50; color: white; padding: 10px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .otp { font-size: 24px; font-weight: bold; text-align: center; padding: 10px; background-color: #e0e0e0; margin: 20px 0; }
            .footer { text-align: center; font-size: 12px; color: #777; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Your One-Time Password</h1>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>You've requested to log in to your account. To ensure the security of your account, please use the following One-Time Password (OTP) to complete your login:</p>
                <div class="otp">{{ otp }}</div>
                <p>This OTP will expire in 5 minutes for security reasons. If you didn't request this login, please ignore this email or contact our support team immediately.</p>
                <p>For your security, never share this OTP with anyone, including our staff. We will never ask you for your OTP outside of the login process.</p>
                <p>Thank you for using our service!</p>
            </div>
            <div class="footer">
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """,
        otp=otp,
    )

    text_body = f"""
    Your One-Time Password (OTP)

    Hello,

    You've requested to log in to your account. To ensure the security of your account, please use the following One-Time Password (OTP) to complete your login:

    {otp}

    This OTP will expire in 5 minutes for security reasons. If you didn't request this login, please ignore this email or contact our support team immediately.

    For your security, never share this OTP with anyone, including our staff. We will never ask you for your OTP outside of the login process.

    Thank you for using our service!

    This is an automated message, please do not reply to this email.
    """

    msg = Message(subject, recipients=[email])
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


def generate_tokens(user):
    # Define expiration for access token
    access_token_expires = datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRES_IN
    access_token_payload = {
        "user_id": str(user.id),
        "username": user.username,
        "email": user.email,
        "exp": access_token_expires,
    }

    # Create access token
    access_token = jwt.encode(access_token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Define expiration for refresh token
    refresh_token_expires = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRES_IN
    refresh_token_payload = {
        "user_id": str(user.id),
        "exp": refresh_token_expires,
    }

    # Create refresh token
    refresh_token = jwt.encode(
        refresh_token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM
    )

    # Create a new session in the database
    session_id = str(uuid4())
    new_session = Session(
        id=session_id,
        user_id=user.id,
        jwt_token=access_token,
        refresh_token=refresh_token,
        expires_at=refresh_token_expires,
    )

    try:
        db.session.add(new_session)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        raise

    return access_token, refresh_token, session_id


# User Registration Route
@sso_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            return jsonify({"error": "An error occurred while creating the user"}), 500

        # Redirect the user to the login page after successful registration
        return redirect(url_for("login"))
    return render_template("register.html")


# User Login Route
@sso_bp.route("/login", methods=["GET", "POST"])
def email_login():
    data = request.form  # Handle form data instead of JSON
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    if user.otp_enabled:
        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = datetime.now(timezone.utc) + OTP_EXPIRATION_TIME
        db.session.commit()
        send_otp_email(user.email, otp)
        return redirect(url_for("sso.verify_otp_page", user_id=user.id))
    else:
        access_token, refresh_token, session_id = generate_tokens(user)
        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=ACCESS_TOKEN_EXPIRES_IN.total_seconds(),
        )
        response.set_cookie(
            "refresh_token",
            refresh_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
        )
        response.set_cookie(
            "session_id",
            session_id,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
        )
        return response


# Password Reset Request Route
@sso_bp.route("/reset_password_request", methods=["POST"])
def reset_password_request():
    data = request.json
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now(timezone.utc) + OTP_EXPIRATION_TIME

    try:
        db.session.commit()
        send_otp_email(user.email, otp)
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "An error occurred while generating OTP"}), 500

    return jsonify({"message": "OTP sent to the provided email address"}), 200


# Password Reset Verification Route
@sso_bp.route("/reset_password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")

    if not email or not otp or not new_password:
        return jsonify({"error": "Email, OTP, and new password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    current_time = datetime.now(timezone.utc)
    if (
        user.otp
        and user.otp == otp
        and user.otp_expiry
        and current_time < user.otp_expiry
    ):
        user.password_hash = generate_password_hash(new_password)
        user.otp = None
        user.otp_expiry = None
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            return (
                jsonify({"error": "An error occurred while resetting the password"}),
                500,
            )
        return jsonify({"message": "Password reset successfully"}), 200
    else:
        return jsonify({"error": "Invalid or expired OTP"}), 400


@sso_bp.route("/login/<provider>")
def login(provider):
    try:
        if provider not in ["google", "facebook", "github", "jira"]:
            return jsonify({"error": "Invalid OAuth provider"}), 400
        redirect_uri = url_for("sso.auth", provider=provider, _external=True)
        return oauth.create_client(provider).authorize_redirect(redirect_uri)
    except Exception as e:
        return jsonify({"error": "An error occurred during login"}), 500


@sso_bp.route("/auth/<provider>")
def auth(provider):
    try:

        if provider not in ["google", "facebook", "github", "jira"]:
            return jsonify({"error": "Invalid OAuth provider"}), 400

        oauth_client = oauth.create_client(provider)
        token = oauth_client.authorize_access_token()

        if provider == "github":
            resp = oauth_client.get("user")
            resp.raise_for_status()
            user_info = resp.json()
            try:
                emails_resp = oauth_client.get("user/emails")
                emails_resp.raise_for_status()
                emails = emails_resp.json()
                primary_email = next(
                    (email["email"] for email in emails if email["primary"]), None
                )
                user_info["email"] = primary_email
            except Exception as e:
                user_info["email"] = user_info.get("email")

            if not user_info.get("email"):
                return (
                    jsonify(
                        {
                            "error": "Unable to retrieve email from GitHub. Please make sure your GitHub email is public or grant email access to the application."
                        }
                    ),
                    400,
                )

        elif provider == "jira":
            resp = oauth_client.get("https://api.atlassian.com/me")
            resp.raise_for_status()
            user_info = resp.json()

            account_id = user_info.get("account_id")
            if not account_id:
                return (
                    jsonify({"error": "Unable to retrieve account ID from Jira"}),
                    400,
                )

            email = user_info.get("email")
            if not email:
                account_resp = oauth_client.get(
                    f"https://api.atlassian.com/users/{account_id}"
                )
                account_resp.raise_for_status()
                account_info = account_resp.json()
                email = account_info.get("email")

            if not email:
                return jsonify({"error": "Unable to retrieve email from Jira"}), 400

            user_info["id"] = account_id
            user_info["email"] = email

        elif provider == "google":
            resp = oauth_client.get("https://www.googleapis.com/oauth2/v3/userinfo")
            resp.raise_for_status()
            user_info = resp.json()

        elif provider == "facebook":
            resp = oauth_client.get("/me?fields=id,name,email")
            resp.raise_for_status()
            user_info = resp.json()

        provider_user_id = str(
            user_info.get("id") or user_info.get("sub") or user_info.get("account_id")
        )
        email = user_info.get("email")

        if not email:
            return jsonify({"error": f"Unable to retrieve email from {provider}"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:

            user = User(
                username=user_info.get("name")
                or user_info.get("login")
                or user_info.get("nickname", f"user_{provider_user_id}"),
                email=email,
            )
            db.session.add(user)
            db.session.flush()
            db.session.commit()

        oauth_provider = OAuthProvider.query.filter_by(
            user_id=user.id, provider=provider
        ).first()
        if not oauth_provider:
            oauth_provider = OAuthProvider(
                user_id=user.id, provider=provider, provider_user_id=provider_user_id
            )
            db.session.add(oauth_provider)
            db.session.commit()

        if user.otp_enabled:
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.now(timezone.utc) + OTP_EXPIRATION_TIME
            db.session.commit()
            send_otp_email(user.email, otp)
            return redirect(url_for("sso.verify_otp_page", user_id=user.id))
        else:
            access_token, refresh_token, session_id = generate_tokens(user)
            response = make_response(redirect(url_for("dashboard")))
            response.set_cookie(
                "access_token",
                access_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=ACCESS_TOKEN_EXPIRES_IN.total_seconds(),
            )
            response.set_cookie(
                "refresh_token",
                refresh_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
            )
            response.set_cookie(
                "session_id",
                session_id,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
            )
            return response

    except OAuth2Error as e:
        print(f"OAuth2Error: {str(e)}")
        return (
            jsonify({"error": f"Authentication error with {provider}: {str(e)}"}),
            400,
        )
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return (
            jsonify(
                {
                    "error": f"An unexpected error occurred during {provider} authentication"
                }
            ),
            500,
        )


@sso_bp.route("/verify_otp_page/<int:user_id>")
def verify_otp_page(user_id):
    return render_template("verify_otp.html", user_id=user_id)


@sso_bp.route("/verify_otp/<int:user_id>", methods=["POST"])
def verify_otp(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.json
    otp = data.get("otp", "").strip()
    current_time = datetime.now(timezone.utc)

    if user.otp and user.otp == otp and user.otp_expiry:
        otp_expiry = (
            user.otp_expiry.replace(tzinfo=timezone.utc)
            if user.otp_expiry.tzinfo is None
            else user.otp_expiry
        )

        if current_time < otp_expiry:
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            access_token, refresh_token, session_id = generate_tokens(user)
            response = make_response(jsonify({"message": "OTP verified successfully"}))
            response.set_cookie(
                "access_token",
                access_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=ACCESS_TOKEN_EXPIRES_IN.total_seconds(),
            )
            response.set_cookie(
                "refresh_token",
                refresh_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
            )
            response.set_cookie(
                "session_id",
                session_id,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
            )
            return response, 200
        else:
            return jsonify({"error": "OTP has expired"}), 400
    else:
        return jsonify({"error": "Invalid OTP"}), 400


@sso_bp.route("/resend_otp/<int:user_id>", methods=["POST"])
def resend_otp(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now(timezone.utc) + OTP_EXPIRATION_TIME
    db.session.commit()
    send_otp_email(user.email, otp)

    return jsonify({"message": "New OTP sent successfully"}), 200


@sso_bp.route("/enable_2fa", methods=["POST"])
@verify_token
def enable_2fa():
    user = g.user
    if user.otp_enabled:
        return jsonify({"error": "2FA is already enabled"}), 400
    user.otp_enabled = True
    db.session.commit()
    return jsonify({"message": "2FA enabled successfully"}), 200


@sso_bp.route("/disable_2fa", methods=["POST"])
@verify_token
def disable_2fa():
    user = g.user
    if not user.otp_enabled:
        return jsonify({"error": "2FA is not enabled"}), 400
    user.otp_enabled = False
    user.otp = None
    user.otp_expiry = None
    db.session.commit()
    return jsonify({"message": "2FA disabled successfully"}), 200


@sso_bp.route("/refresh_token", methods=["POST"])
def refresh_token():
    try:
        refresh_token = request.cookies.get("refresh_token")
        session_id = request.cookies.get("session_id")
        if not refresh_token or not session_id:
            return jsonify({"error": "No refresh token or session provided"}), 400

        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = User.query.get(payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        session = Session.query.filter_by(id=session_id, user_id=user.id).first()
        if not session or session.refresh_token != refresh_token:
            return jsonify({"error": "Invalid session"}), 401

        new_access_token, new_refresh_token, new_session_id = generate_tokens(user)

        # Delete the old session
        db.session.delete(session)
        db.session.commit()

        response = make_response(jsonify({"message": "Token refreshed successfully"}))
        response.set_cookie(
            "access_token",
            new_access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=ACCESS_TOKEN_EXPIRES_IN.total_seconds(),
        )
        response.set_cookie(
            "refresh_token",
            new_refresh_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
        )
        response.set_cookie(
            "session_id",
            new_session_id,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRES_IN.total_seconds(),
        )
        return response, 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401
    except Exception as e:
        return jsonify({"error": "An error occurred during token refresh"}), 500


@sso_bp.route("/logout")
@verify_token
def logout():
    session = g.session
    db.session.delete(session)
    db.session.commit()

    response = make_response(jsonify({"message": "Logged out successfully"}))
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("session_id")
    return response


@sso_bp.route("/policy")
def policy():
    # This is a placeholder for your actual policy content
    policy_content = """
    <h1>Privacy Policy</h1>
    <p>This is a placeholder for your privacy policy content.</p>
    <p>Please replace this with your actual privacy policy.</p>
    """
    return policy_content, 200, {"Content-Type": "text/html"}
