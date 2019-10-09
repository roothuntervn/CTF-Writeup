from flask import Flask
from app.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
import time,atexit
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
bootstrap=Bootstrap(app)

from app import routes,models

def DB_init(db):
    db.drop_all()
    db.create_all()

    u = models.User(username='jarrett.booz',password_hash='deadbeef',id=1,admin=0,secret='Likes Oreos.', name="Jarrett Booz")    
    db.session.add(u)
    
    u = models.User(username='danny.tunitis',password_hash='deadbeef',id=2,admin=0,secret='Know it all.', name= "Danny Tunitis")    
    db.session.add(u)    
    
    c = models.Todo(item='Shrink the moon', user_id=1)
    db.session.add(c)
    
    c = models.Todo(item='Grab the moon', user_id=1)
    db.session.add(c)
    
    c = models.Todo(item='Sit on the toilet', user_id=1)
    db.session.add(c)

    c = models.Todo(item='Make 2000 more Pico problems', user_id=2)
    db.session.add(c)

    c = models.Todo(item='Do dastardly plan: picoCTF{cookies_are_a_sometimes_food_e53b6d53}', user_id=2)
    db.session.add(c)

    c = models.Todo(item='Buy milk', user_id=2)
    db.session.add(c)
    
    db.session.commit()

try:
    DB_init(db)
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=DB_init,args=(db,),trigger="interval",hours=2)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())
except Exception as e:
    print(e)