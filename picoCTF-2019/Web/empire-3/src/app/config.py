import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = 'ce6a474e832ece298c50448e1feb069d'
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DATABSE_URL') or 'sqlite:///'+os.path.join(basedir,'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False