from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/data.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean, default=False)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(cls):
    @wraps(cls)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is Invalid'}), 401
        return cls(current_user,*args,*kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You are not Admin'})

    users = User.query.all()
    data = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        data.append(user_data)
    return jsonify({'user':data})


@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_selected_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'You are not Admin'})
    return ''


@app.route('/user', methods=['POST'])
def create_new_user():
    data = request.get_json()
    password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User success full created'})


@app.route('/user/<user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'You are not Admin'})
    return ''


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'You are not Admin'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"Message": "User Not Found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"Message": "User Has Been Deleted"})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login'
                                                                           'Required"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'public_id': user.public_id,'exp': datetime.datetime.utcnow()+datetime.timedelta(days=1)}, app.config['SECRET_KEY'])
        return jsonify({'message': 'Your Token Successful Created',
                        'token': token.decode('UTF-8'),
                        'Expired': datetime.datetime.utcnow()+datetime.timedelta(days=1)})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})


@app.route('/todo',methods=['GET'])
@token_required
def get_all_todo(current_user):
    tasks = Todo.query.filter_by(user_id=current_user.id).all()
    data = []
    for task in tasks:
        task_data = {}
        task_data['id'] = task.id
        task_data['text'] = task.text
        task_data['complete'] = task.complete
        data.append(task_data)
    return jsonify({'todo': data})

@app.route('/todo/<todo_id>',methods=['GET'])
@token_required
def get_selected_todo(current_user, todo_id):
    task = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Todo Not Found!'})
    task_data = {}
    task_data['id'] = task.id
    task_data['text'] = task.text
    task_data['complete'] = task.complete
    return jsonify({'message': 'Todo Found',
                    'todo': task_data})


@app.route('/todo',methods=['POST'])
@token_required
def todo_create(current_user):
    data = request.get_json()
    todo_task = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(todo_task)
    db.session.commit()
    return jsonify({'message': 'Todo Successful Created'})


@app.route('/todo/<todo_id>',methods=['PUT'])
@token_required
def todo_update(current_user, todo_id):
    return ''


@app.route('/todo/<todo_id>',methods=['DELETE'])
@token_required
def todo_delete(current_user, todo_id):
    return ''


if __name__ == '__main__':
    app.run(port=1000,debug=True)
