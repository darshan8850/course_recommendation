from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, Boolean
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import Table, ForeignKey
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
import os
from dotenv import load_dotenv
from sqlalchemy import LargeBinary
import base64
from datetime import datetime
from flask_socketio import emit
from flask_socketio import SocketIO


load_dotenv()

connection_string = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

engine = create_engine(connection_string)

Base = declarative_base()

user_mentor_association = Table('user_mentor_association', Base.metadata,
                                Column('user_id', Integer, ForeignKey('users.id')),
                                Column('mentor_id', Integer, ForeignKey('mentors.id'))
                                )

class Admin(Base):
    __tablename__ = 'admins'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)


class Stream(Base):
    __tablename__ = 'streams'

    name = Column(String, primary_key=True, nullable=False)


class Mentor(Base):
    __tablename__ = 'mentors'

    id = Column(Integer, primary_key=True)
    mentor_name = Column(String)
    profile_photo = Column(LargeBinary)  
    description = Column(String)
    highest_degree = Column(String)
    expertise = Column(String)
    recent_project = Column(String)
    meeting_time = Column(String)
    fees = Column(String)
    stream_name = Column(String, ForeignKey('streams.name')) 
    country = Column(String)
    verified = Column(Boolean, default=False)
 
    stream = relationship("Stream", backref="mentors") 


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    google_id = Column(String)

    # Establishing a One-to-One relationship with UserDetails
    details = relationship("UserDetails", back_populates="user", uselist=False)

    # Establishing a Many-to-Many relationship with Mentor
    mentors = relationship("Mentor", secondary=user_mentor_association)


class UserDetails(Base):
    __tablename__ = 'user_details'

    id = Column(Integer, primary_key=True)
    username = Column(String, ForeignKey('users.username'), unique=True)
    first_name = Column(String)
    last_name = Column(String)
    school_name = Column(String)
    bachelors_degree = Column(String)
    masters_degree = Column(String)
    certification = Column(String)
    activity = Column(String)
    country = Column(String)
    data_filled = Column(Boolean, default=False)
    stream_name = Column(String, ForeignKey('streams.name')) 

    user = relationship("User", back_populates="details")
    stream = relationship("Stream", backref="user_details") 
    
class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('mentors.id'), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", backref="sent_messages", foreign_keys=[sender_id])
    receiver = relationship("Mentor", backref="received_messages", foreign_keys=[receiver_id])


Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = "123456"

app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'figurecircle2024@gmail.com'
app.config['MAIL_PASSWORD'] = 'xcodehmmdifkilyw'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False



google_client_id = os.getenv('GOOGLE_CLIENT_ID')
google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET')

app.config['GOOGLE_CLIENT_ID'] = google_client_id
app.config['GOOGLE_CLIENT_SECRET'] = google_client_secret

app.config['GOOGLE_DISCOVERY_URL'] = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

mail = Mail(app)
socketio = SocketIO(app)
jwt = JWTManager(app)

client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])


@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Recommendation API!"})


@app.route('/google_login')
def google_login():
    google_provider_cfg = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route('/google_login/callback')
def google_callback():
    code = request.args.get("code")
    token_endpoint = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(app.config['GOOGLE_CLIENT_ID'], app.config['GOOGLE_CLIENT_SECRET']),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        user_name = userinfo_response.json()["given_name"]

        session = Session()

        user = session.query(User).filter_by(google_id=unique_id).first()
        if not user:
            # Create a new user account if not existing
            user = User(username=users_email, google_id=unique_id)
            session.add(user)
            session.commit()

        data_fill = user.details.data_filled if user.details else False

        access_token = create_access_token(identity=user.username, expires_delta=False)
        session.close()
        return jsonify({"access_token": access_token, "data_fill": data_fill}), 200
    else:
        return jsonify({"error": "User email not available or not verified by Google"}), 400

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()

    # Check if the username already exists
    if session.query(User).filter_by(username=username).first():
        session.close()
        return jsonify({"message": "Username already exists"}), 400

    # Create a new user
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    session.add(new_user)

    # Create empty user details for the new user
    new_user_details = UserDetails(user=new_user)
    session.add(new_user_details)

    session.commit()
    session.close()

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()

    # Retrieve the user by username
    user = session.query(User).filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        session.close()
        return jsonify({"message": "Invalid username or password"}), 401

    # Check if user details are filled
    data_fill = user.details.data_filled if user.details else False

    access_token = create_access_token(identity=username, expires_delta=False)
    session.close()
    return jsonify({"access_token": access_token, "data_fill": data_fill}), 200

@app.route('/register_admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)
    new_admin = Admin(username=username, password=hashed_password)

    session = Session()
    session.add(new_admin)
    session.commit()
    session.close()

    return jsonify({"message": "Admin registered successfully"}), 201

@app.route('/admin_login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()
    admin = session.query(Admin).filter_by(username=username).first()

    if not admin or not check_password_hash(admin.password, password):
        session.close()
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=username, expires_delta=False)
    session.close()
    return jsonify({"access_token": access_token}), 200

@app.route('/user_details', methods=['GET', 'POST'])
@jwt_required()
def user_details():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    if request.method == 'GET':
        user_details = user.details
        session.close()
        if user_details:
            user_details_dict = {
                "first_name": user_details.first_name,
                "last_name": user_details.last_name,
                "school_name": user_details.school_name,
                "bachelors_degree": user_details.bachelors_degree,
                "masters_degree": user_details.masters_degree,
                "certification": user_details.certification,
                "activity": user_details.activity,
                "country": user_details.country,
                "stream_name": user_details.stream_name, 
                "data_filled": user_details.data_filled
            }
            return jsonify(user_details_dict), 200
        else:
            return jsonify({"message": "User details not found"}), 200

    elif request.method == 'POST':
        data = request.get_json()

        if user.details and user.details.data_filled:
            session.close()
            return jsonify({"message": "User details already exist"}), 400

        if not user.details:
            user.details = UserDetails(user=user)

        user.details.first_name = data.get('first_name', user.details.first_name)
        user.details.last_name = data.get('last_name', user.details.last_name)
        user.details.school_name = data.get('school_name', user.details.school_name)
        user.details.bachelors_degree = data.get('bachelors_degree', user.details.bachelors_degree)
        user.details.masters_degree = data.get('masters_degree', user.details.masters_degree)
        user.details.certification = data.get('certification', user.details.certification)
        user.details.activity = data.get('activity', user.details.activity)
        user.details.country = data.get('country', user.details.country)
        user.details.stream_name = data.get('stream_name', user.details.stream_name) 

        user.details.data_filled = True

        try:
            session.commit()
            session.close()
            return jsonify({"message": "User details added/updated successfully"}), 200
        except Exception as e:
            session.rollback()
            session.close()
            return jsonify({"message": f"Failed to add/update user details: {str(e)}"}), 500


@app.route('/streams', methods=['POST'])
@jwt_required()
def create_stream():
    data = request.get_json()
    stream_name = data.get('name')

    if not stream_name:
        return jsonify({"message": "Stream name is required"}), 400

    session = Session()
    new_stream = Stream(name=stream_name)

    try:
        session.add(new_stream)
        session.commit()
        session.close()
        return jsonify({"message": "Stream created successfully"}), 201
    except IntegrityError:
        session.rollback()
        session.close()
        return jsonify({"message": "Stream name already exists"}), 400

@app.route('/streams/<string:stream_name>', methods=['PUT'])
@jwt_required()
def update_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    data = request.get_json()
    new_name = data.get('name')

    if not new_name:
        session.close()
        return jsonify({"message": "New stream name is required"}), 400

    stream.name = new_name

    try:
        session.commit()
        session.close()
        return jsonify({"message": "Stream updated successfully"}), 200
    except IntegrityError:
        session.rollback()
        session.close()
        return jsonify({"message": "New stream name already exists"}), 400

@app.route('/streams/<string:stream_name>', methods=['DELETE'])
@jwt_required()
def delete_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    session.delete(stream)
    session.commit()
    session.close()

    return jsonify({"message": "Stream deleted successfully"}), 200

@app.route('/streams/<string:stream_name>', methods=['GET'])
@jwt_required()
def get_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    stream_info = {
        "name": stream.name
    }

    session.close()
    return jsonify(stream_info), 200

@app.route('/streams', methods=['GET'])
@jwt_required()
def list_streams():
    session = Session()

    streams = session.query(Stream).all()

    stream_list = [stream.name for stream in streams]

    session.close()
    return jsonify({"streams": stream_list}), 200

@app.route('/add_mentor', methods=['POST'])
@jwt_required()
def add_mentor():
    current_user = get_jwt_identity()
    session = Session()

    data = request.get_json()
    mentor_name = data.get('mentor_name')
    profile_photo_base64 = data.get('profile_photo')  # profile photo is sent as base64-encoded string
    description = data.get('description')
    highest_degree = data.get('highest_degree')
    expertise = data.get('expertise')
    recent_project = data.get('recent_project')
    meeting_time = data.get('meeting_time')
    fees = data.get('fees')
    stream_name = data.get('stream')  
    country = data.get('country')
    sender_email = data.get('sender_email')

    if not all([mentor_name, profile_photo_base64, description, highest_degree, expertise, recent_project, meeting_time, fees, stream_name, country]):
        session.close()
        return jsonify({"message": "Missing mentor details"}), 400

    try:

        profile_photo_binary = base64.b64decode(profile_photo_base64)

        stream = session.query(Stream).filter_by(name=stream_name).first()
        if not stream:
            session.close()
            return jsonify({"message": "Stream does not exist"}), 404

        # Create a new mentor with the provided details
        new_mentor = Mentor(
            mentor_name=mentor_name, profile_photo=profile_photo_binary, description=description,
            highest_degree=highest_degree, expertise=expertise, recent_project=recent_project,
            meeting_time=meeting_time, fees=fees, stream_name=stream_name, country=country, verified=False
        )
        session.add(new_mentor)
        session.commit()

        msg = Message('New Mentor Verification', sender=sender_email, recipients=['admin_email@example.com'])
        msg.body = f"Please verify the new mentor:\n\nID: {new_mentor.id}\nName: {mentor_name}\nStream: {stream_name}\nCountry: {country}"
        mail.send(msg)

        session.close()
        return jsonify({"message": "Mentor added successfully. Verification email sent to admin."}), 201
    except Exception as e:
        session.close()
        return jsonify({"message": f"Failed to add mentor: {str(e)}"}), 500


@app.route('/update_mentor/<int:mentor_id>', methods=['PUT'])
@jwt_required()
def update_mentor(mentor_id):
    session = Session()

    # Query the mentor by mentor_id
    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    # Get updated data from request body
    data = request.get_json()
    mentor_name = data.get('mentor_name')
    description = data.get('description')
    highest_degree = data.get('highest_degree')
    expertise = data.get('expertise')
    recent_project = data.get('recent_project')
    meeting_time = data.get('meeting_time')
    fees = data.get('fees')
    stream_name = data.get('stream')
    country = data.get('country')

    # Update mentor details
    if mentor_name:
        mentor.mentor_name = mentor_name
    if description:
        mentor.description = description
    if highest_degree:
        mentor.highest_degree = highest_degree
    if expertise:
        mentor.expertise = expertise
    if recent_project:
        mentor.recent_project = recent_project
    if meeting_time:
        mentor.meeting_time = meeting_time
    if fees:
        mentor.fees = fees
    if stream_name:
        mentor.stream_name = stream_name
    if country:
        mentor.country = country

    session.commit()
    session.close()

    return jsonify({"message": "Mentor details updated successfully"}), 200


@app.route('/mentors_by_stream', methods=['GET'])
@jwt_required()
def mentors_by_stream():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    user_details = user.details
    if not user_details or not user_details.stream_chosen:
        session.close()
        return jsonify({"message": "User stream not found"}), 404

    user_stream = user_details.stream_chosen

    try:
    
        mentors = session.query(Mentor).filter_by(stream=user_stream).all()

        mentor_list = []
        for mentor in mentors:
            mentor_info = {
                "mentor_id": mentor.id,
                "mentor_name": mentor.mentor_name,
                "profile_photo": mentor.profile_photo.decode('utf-8'),  
                "description": mentor.description,
                "highest_degree": mentor.highest_degree,
                "expertise": mentor.expertise,
                "recent_project": mentor.recent_project,
                "meeting_time": mentor.meeting_time,
                "fees": mentor.fees,
                "stream": mentor.stream,
                "country": mentor.country,
                "verified": mentor.verified
            }
            mentor_list.append(mentor_info)

        session.close()
        return jsonify({"mentors_with_same_stream": mentor_list}), 200
    except Exception as e:
        session.close()
        return jsonify({"message": f"Failed to retrieve mentors: {str(e)}"}), 500



@app.route('/admin/verify_mentor/<int:mentor_id>', methods=['PUT'])
@jwt_required()
def admin_verify_mentor(mentor_id):
    current_user = get_jwt_identity()

    session = Session()
    admin = session.query(Admin).filter_by(username=current_user).first()

    if not admin:
        session.close()
        return jsonify({"message": "Unauthorized"}), 401

    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    mentor.verified = True
    session.commit()
    session.close()

    return jsonify({"message": "Mentor verified successfully"}), 200


@app.route('/verified_mentors', methods=['GET'])
@jwt_required()
def get_verified_mentors():
    current_user = get_jwt_identity()

    # Check if current_user is an admin
    if not is_admin(current_user):
        return jsonify({"message": "Unauthorized"}), 401

    session = Session()

    # Query verified mentors
    verified_mentors = session.query(Mentor).filter_by(verified=True).all()

    mentor_list = []
    for mentor in verified_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "profile_photo": mentor.profile_photo.decode('utf-8'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"verified_mentors": mentor_list}), 200

def is_admin(username):
    session = Session()
    admin = session.query(Admin).filter_by(username=username).first()
    session.close()
    return admin is not None

@app.route('/unverified_mentors', methods=['GET'])
@jwt_required()
def get_unverified_mentors():
    current_user = get_jwt_identity()

    # Check if current_user is an admin
    if not is_admin(current_user):
        return jsonify({"message": "Unauthorized"}), 401

    session = Session()

    # Query unverified mentors
    unverified_mentors = session.query(Mentor).filter_by(verified=False).all()

    mentor_list = []
    for mentor in unverified_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "profile_photo": mentor.profile_photo.decode('utf-8'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"unverified_mentors": mentor_list}), 200


@app.route('/assign_mentor', methods=['POST'])
@jwt_required()
def assign_mentor():
    current_user = get_jwt_identity()
    session = Session()
    
    data = request.get_json()
    mentor_id = data.get('mentor_id')
    user_id = data.get('user_id')

    mentor = session.query(Mentor).filter_by(id=mentor_id).first()
    user = session.query(User).filter_by(id=user_id).first()

    if not mentor or not user:
        session.close()
        return jsonify({"message": "Mentor or user not found"}), 404

    # Assign the mentor to the user
    user.mentors.append(mentor)
    session.commit()
    session.close()

    return jsonify({"message": f"Mentor {mentor_id} assigned to user {user_id} successfully"}), 200

'''
@app.route('/add_stream_chosen', methods=['PUT'])
@jwt_required()
def add_stream_chosen():
    current_user = get_jwt_identity()  # Retrieve username from the JWT token
    
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    stream_chosen = data.get('stream_chosen')

    if not stream_chosen:
        session.close()
        return jsonify({"message": "Stream chosen is required"}), 400

    user_details = user.details
    if not user_details:
        user_details = UserDetails(user=user)

    user_details.stream_chosen = stream_chosen
    user_details.data_filled = True  # Assuming this field should be marked as filled

    session.commit()
    session.close()

    return jsonify({"message": "Stream chosen updated successfully"}), 200

'''

@app.route('/assigned_mentors', methods=['GET'])
@jwt_required()
def get_assigned_mentors():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    assigned_mentors = user.mentors  # Fetch assigned mentors using the relationship

    mentor_list = []
    for mentor in assigned_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "profile_photo": mentor.profile_photo.decode('utf-8'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"assigned_mentors": mentor_list}), 200

"""

@app.route('/chosen_stream', methods=['GET'])
@jwt_required()
def get_chosen_stream():
    current_user = get_jwt_identity()

    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    user_details = user.details

    if not user_details:
        session.close()
        return jsonify({"message": "User details not found"}), 404

    chosen_stream = user_details.stream_chosen

    session.close()

    return jsonify({"chosen_stream": chosen_stream}), 200

"""

@app.route('/assigned_users', methods=['GET'])
@jwt_required()
def get_assigned_users():
    current_user = get_jwt_identity()

    session = Session()

    # Query the mentor associated with the current authenticated user
    mentor = session.query(Mentor).join(User.mentors).filter(User.username == current_user).first()

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found for the current user"}), 404

    assigned_users = mentor.users  # Fetch assigned users using the relationship

    user_list = []
    for user in assigned_users:
        user_info = {
            "user_id": user.id,
            "username": user.username,
            "first_name": user.details.first_name if user.details else None,
            "last_name": user.details.last_name if user.details else None,
            "email": user.username,  # Assuming username is the email
        }
        user_list.append(user_info)

    session.close()

    return jsonify({"assigned_users": user_list}), 200

@socketio.on('send_message')
def handle_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')

    sender = User.query.get(sender_id)
    receiver = Mentor.query.get(receiver_id)
    
    session = Session()

    if not sender or not receiver:
        emit('message_status', {'success': False, 'message': 'Sender or receiver not found'})
        return

    new_message = Message(sender_id=sender_id, receiver_id=receiver_id, message=message_text)
    session.add(new_message)
    session.commit()
    session.close()

    emit('receive_message', {'sender_id': sender_id, 'message': message_text}, room=receiver_id)

# Delete All Users Endpoint
@app.route('/delete_users', methods=['DELETE'])
@jwt_required()
def delete_users():
    current_user = get_jwt_identity()
    session = Session()

    session.query(User).delete()
    session.commit()
    session.close()

    return jsonify({"message": "All users deleted successfully"}), 200

# Delete All Mentors Endpoint
@app.route('/delete_mentors', methods=['DELETE'])
@jwt_required()
def delete_mentors():
    current_user = get_jwt_identity()
    session = Session()

    session.query(Mentor).delete()
    session.commit()
    session.close()

    return jsonify({"message": "All mentors deleted successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)

                    
