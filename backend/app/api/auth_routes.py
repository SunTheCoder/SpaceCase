from flask import Blueprint, request
from flask_login import current_user, login_user, logout_user

from app.forms import LoginForm, SignUpForm
from app.models import User, db

auth_routes = Blueprint('auth', __name__)


@auth_routes.route('/')
def authenticate():
	"""
	Authenticates a user.
	"""
	if current_user.is_authenticated:
		return current_user.to_dict()
	return {'errors': {'message': 'Unauthorized'}}, 401


@auth_routes.route('/login', methods=['POST'])
def login():
	"""
	Logs a user in
	"""
	form = LoginForm()
	# Get the csrf_token from the request cookie and put it into the
	# form manually to validate_on_submit can be used
	form['csrf_token'].data = request.cookies['csrf_token']
	if form.validate_on_submit():
		# Add the user to the session, we are logged in!
		user = User.query.filter(User.email == form.data['email']).first()
		login_user(user)
		return user.to_dict()
	return form.errors, 401

@auth_routes.route('/update', methods=['PUT'])

def update_user():
    """
    Updates the current user's information
    """
    try:
        data = request.get_json()

        # Allowed fields to update
        allowed_fields = ['username', 'email', 'password', 'wallet_address']
        updates = {key: value for key, value in data.items() if key in allowed_fields}

        if not updates:
            return {'errors': {'message': 'No valid fields to update'}}, 400

        # Update fields
        for key, value in updates.items():
            if key == 'password':
                current_user.password = value  # Hashing handled by model setter
            else:
                setattr(current_user, key, value)

        # Commit the updates
        db.session.commit()

        return current_user.to_dict(), 200
    except Exception as e:
        print(f"Error updating user: {e}")
        return {'errors': {'message': 'Internal server error'}}, 500



@auth_routes.route('/logout')
def logout():
	"""
	Logs a user out
	"""
	logout_user()
	return {'message': 'User logged out'}


@auth_routes.route('/signup', methods=['POST'])
def sign_up():
	"""
	Creates a new user and logs them in
	"""
	print("Signup request received")
	print("Request data:", request.get_json())
	print("CSRF token in cookie:", request.cookies.get('csrf_token'))
	print("CSRF token in header:", request.headers.get('X-CSRF-Token'))
	
	form = SignUpForm()
	form['csrf_token'].data = request.cookies['csrf_token']
	
	if form.validate_on_submit():
		user = User(
			username=form.data['username'],
			email=form.data['email'],
			password=form.data['password']
		)
		db.session.add(user)
		db.session.commit()
		login_user(user)
		return user.to_dict()
	
	print("Form validation errors:", form.errors)
	return form.errors, 401



@auth_routes.route('/unauthorized')
def unauthorized():
	"""
	Returns unauthorized JSON when flask-login authentication fails
	"""
	return {'errors': {'message': 'Unauthorized'}}, 401
