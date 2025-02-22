import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session
from flask_cors import CORS
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf

from .api.auth_routes import auth_routes
from .api.upload_routes import upload_routes
from .api.user_routes import user_routes
from .api.wallet_routes import wallet_routes
from .config import Config
from .models import User, db
from .seeds import seed_commands

load_dotenv()  # Load environment variables from .env

app = Flask(__name__, static_folder='../../frontend/dist/', static_url_path='/')

# Setup login manager
login = LoginManager(app)
login.login_view = 'auth.unauthorized'


@login.user_loader
def load_user(id):
	return User.query.get(int(id))


# Tell flask about our seed commands
app.cli.add_command(seed_commands)

app.config.from_object(Config)
app.register_blueprint(user_routes, url_prefix='/api/users')
app.register_blueprint(auth_routes, url_prefix='/api/auth')
app.register_blueprint(wallet_routes, url_prefix='/api/wallets')
app.register_blueprint(upload_routes, url_prefix='/api/uploads')
db.init_app(app)
Migrate(app, db)

# After db.init_app(app)
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print("Database initialization error:", str(e))

# Application Security
CORS(app, 
     resources={
         r"/api/*": {
             "origins": ["https://spacecase.vercel.app"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "X-CSRF-Token"],
             "expose_headers": ["Content-Type", "X-CSRF-Token", "Set-Cookie"],
             "supports_credentials": True
         }
     })


# Since we are deploying with Docker and Flask,
# we won't be using a buildpack when we deploy to Heroku.
# Therefore, we need to make sure that in production any
# request made over http is redirected to https.
# Well.........
@app.before_request
def https_redirect():
	if os.environ.get('FLASK_ENV') == 'production':
		if request.headers.get('X-Forwarded-Proto') == 'http':
			url = request.url.replace('http://', 'https://', 1)
			code = 301
			return redirect(url, code=code)


@app.after_request
def after_request(response):
    # CSRF token
    if 'csrf_token' not in request.cookies:
        response.set_cookie(
            'csrf_token',
            generate_csrf(),
            secure=True,
            samesite='None',
            httponly=False,
            domain=None
        )
    
    # Remove manual CORS headers - let Flask-CORS handle it
    return response


@app.route('/api/docs')
def api_help():
	"""
	Returns all API routes and their doc strings
	"""
	acceptable_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
	route_list = {
		rule.rule: [
			[method for method in rule.methods if method in acceptable_methods],
			app.view_functions[rule.endpoint].__doc__,
		]
		for rule in app.url_map.iter_rules()
		if rule.endpoint != 'static'
	}
	return route_list


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def react_root(path):
    """
    This route will direct to the public directory in our
    react builds in the production environment for favicon
    or index.html requests
    """
    try:
        if path == 'favicon.ico':
            return app.send_from_directory('public', 'favicon.ico')
        return app.send_static_file('index.html')
    except Exception as e:
        print(f"Error serving static file: {e}")
        return app.send_static_file('index.html')


@app.errorhandler(404)
def not_found(e):
	return app.send_static_file('index.html')
