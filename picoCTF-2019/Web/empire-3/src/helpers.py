from app import db,login
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64),index=True,unique=True)
    name = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    secret = db.Column(db.String(128),default="picoCTF{cookies_are_a_sometimes_food_e53b6d53}")
    admin = db.Column(db.Integer,default=0)
    
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)
    

class Todo(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    item = db.Column(db.String(256))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))
        
    def __repr__(self):
        return '<Todo {}>'.format(self.id)