from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel, validator
import pandas as pd

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-should-not-be-stored-in-this-file'  
db = SQLAlchemy(app)
jwt = JWTManager(app)

# SQLAlchemy Task Model
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    done = db.Column(db.Boolean, default=False)

# Pydantic Model for Task
class TaskSchema(BaseModel):
    title: str
    description: str = None
    done: bool = False


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Pydantic Model for User Registration
class UserRegistrationSchema(BaseModel):
    username: str
    password: str
    
    @validator('password')
    def validate_password_length(cls, value):
        if len(value) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return value


# Pydantic Model for User Login
class UserLoginSchema(BaseModel):
    username: str
    password: str


@app.route('/tasks', methods=['GET'])
def get_tasks():
    tasks = Task.query.all()
    task_list = [{'id': task.id, 'title': task.title, 'description': task.description, 'done': task.done} for task in tasks]
    return jsonify(task_list)

@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Task not found'}), 404
    return jsonify({'id': task.id, 'title': task.title, 'description': task.description, 'done': task.done})

@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    task_schema = TaskSchema(**data)
    new_task = Task(**task_schema.dict())
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully'}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    data = request.get_json()
    task_schema = TaskSchema(**data)
    task.title = task_schema.title
    task.description = task_schema.description
    task.done = task_schema.done
    db.session.commit()
    return jsonify({'message': 'Task updated successfully'})

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'message': 'Task not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'})



@app.route('/sqlquery', methods=['GET'])
def sql_query():
    query = request.args.get('query')  

    try:
        result = pd.read_sql_query(query, db.engine)  
        return result.to_json(orient='records')
    except Exception as e:
        return jsonify({'error': str(e)}), 500  



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_schema = UserRegistrationSchema(**data)


    if User.query.filter_by(username=user_schema.username).first():
        return jsonify({'message': 'Username already exists'}), 400


    hashed_password = generate_password_hash(user_schema.password, method='sha256')

    if len(user_schema.password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400


    new_user = User(username=user_schema.username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_schema = UserLoginSchema(**data)

    user = User.query.filter_by(username=user_schema.username).first()

    if user and check_password_hash(user.password, user_schema.password):
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # just returning the msg here
    current_user = get_jwt_identity()
    return jsonify({'message': f'Logged out as {current_user}'}), 200


@app.route('/protected', methods=['GET'])
def protected_route():
    authorization_header = request.headers.get('Authorization')

    if authorization_header:
        token = authorization_header.split(' ')[1]
        
       
        return f'Authorization header value: {token}'
    else:
        return 'No Authorization header provided', 401
    
if __name__ == '__main__':
    from flask import current_app

    with app.app_context():
        db.create_all()
    print("this above code has been executed.")

    app.run(debug=True)
