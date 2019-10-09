if __name__ == '__main__':
    print("Please use run.py")
    exit()
    
from flask import render_template,flash,request,redirect,url_for,render_template_string,abort,get_flashed_messages,session
from flask_login import current_user,login_user,logout_user,login_required
from app import app,helpers,db
from app.models import User, Todo
from werkzeug.urls import url_parse

def escape(string):
    vals = {'>':'&#62;','<':'&#60;','\\':'&#92;','/':'&#47;','%':'&#37;'}
    for i in vals.keys():
        string = string.replace(i,vals[i])
    return string

def build_test(task_list):
    mytemplate = '''
    <html>
    <head>
        <title>List</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <nav class="navbar navbar-inverse">
        <div class="container">
        <div class="navbar-header">
            <a class="navbar-brand" href="/index">Evil Empire Company</a>
        </div>
        <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
                <ul class="nav navbar-nav">
            <li><a href='/index'>Home</a></li>
        </ul>
        ''' + ('''
        <ul class="nav navbar-nav navbar-right">
                <li><a href='/login'>Login</a></li>
        </ul>
                <ul class="nav navbar-nav navbar-right">
                    <li><a href='/register'>Register</a></li>
                </ul> ''' if current_user.is_anonymous else '''
                <ul class="nav navbar-nav">
                    <li><a href='/add_item'>Add A Todo</a></li>
                </ul>
                <ul class="nav navbar-nav">
                    <li><a href='/list_items'>Your Todos</a></li>
                </ul>
                <ul class="nav navbar-nav">
                    <li><a href='/employee'>Employee Listing</a></li>
                </ul>
                <ul class="nav navbar-nav navbar-right">
                    <li><a href='/logout'>Logout</a></li>
                </ul>
                <ul class="nav navbar-nav navbar-right">
                    <li><a class="text-capitalize" href="/">''' + current_user.username.replace('{','').replace('}','') + '''</a></li>
                </ul>
            </div>''') + '''</div>
        </nav>
        <h1 class="page-header">Things You Gotta Do</h1>
    <ul class="list-unstyled">
    </body>
    '''

    for task in task_list:
        mytemplate += '''<div class="row">
            <div class="col-md-6">
            <div class="well well-sm">
                <li>
                <strong>Very Urgent: </strong>''' + task.item + '''
                </li> 
            </div>
            </div>
        </div>'''

    mytemplate += '''</ul><script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
    </body>
    </html>'''
    return mytemplate

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html',title='File Not Found')

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html",title="Home")

@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        try:
            return render_template("login.html",title='Login')
        except:
            return redirect(url_for('index'))
    form = helpers.LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=escape(form.username.data)).first()
        if user is None or not user.check_password(escape(form.password.data)):
            flash("Invalid username or password")
            return redirect(url_for('login'))
        login_user(user,remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('list_items')
        return redirect(next_page)
    return render_template('login.html',title='Sign In',form=form)
    
@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = helpers.RegisterForm()
    if form.validate_on_submit():
        user = User(username=escape(form.username.data), name=escape(form.name.data))
        user.set_password(escape(form.password.data))
        db.session.add(user)
        db.session.commit()
        flash("Successfully registered")
        return redirect(url_for("login"))
    return render_template('register.html',title="Register",form=form)

@app.route('/add_item',methods=['GET','POST'])
@login_required
def add_item():
    form = helpers.ItemForm()
    if form.validate_on_submit():
        item = Todo(item=escape(form.item.data),user_id=current_user.id)
        db.session.add(item)
        db.session.commit()
        flash("Item Added")
        return redirect(url_for("add_item")) #("create.html",title="Create",form=form)
    return render_template("create.html",title="Create",form=form)

@app.route('/list_items',methods=['GET'])
@login_required
def list_items():
    item_list=Todo.query.filter_by(user_id=current_user.id)
    if item_list.first() is None:
        item_list=None    
        return render_template("list.html",title="List",items=item_list)

    try:
        return render_template_string(build_test(item_list.all()),title="List")
    except:
        flash("A card is preventing the site from rendering correctly. Please delete it before continuing",category='error')
        return render_template("list.html",title="List",items=item_list)

@app.route('/employee',methods=['GET'])
@login_required
def employee():
    user_list=User.query.all()
    return render_template("employee.html",title="Employee Page" ,users=user_list)

@app.route('/logout',methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))