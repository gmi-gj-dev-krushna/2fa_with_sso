from flask import Flask, render_template
from dotenv import load_dotenv
import os
from models import db
from flask_mail import Mail

mail = Mail()

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    app.config["OAUTHLIB_INSECURE_TRANSPORT"] = False  # Changed to False for production

    # Gmail configuration
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.getenv("GMAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("GMAIL_APP_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("GMAIL_USERNAME")

    db.init_app(app)
    mail.init_app(app)

    from sso import sso_bp, oauth, verify_token

    oauth.init_app(app)

    app.register_blueprint(sso_bp, url_prefix="/sso")

    @app.route("/")
    def index():
        return render_template("login.html")

    @app.route("/login")
    def login():
        return render_template("login.html")

    @app.route("/register")
    def register():
        return render_template("register.html")

    @app.route("/dashboard")
    @verify_token
    def dashboard():
        return render_template("dashboard.html")

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    # Run the app with SSL certificates
    app.run(
        debug=True,
    )
