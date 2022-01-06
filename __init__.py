from datetime import timedelta, datetime
from flask import Flask, render_template, flash, url_for, session, redirect, request, send_file
from sqlalchemy import text  # New
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from Forms import LoginForm, UploadForm, BatchUploadForm, EditForm, OTPForm, ChangePasswordForm, ShareForm
from werkzeug.utils import secure_filename
from io import BytesIO
from humanize import naturalsize
import os
import pyotp
import qrcode
import magic
import uuid
import json
#from faceRecog import authFace

app = Flask(__name__)
app.config["SECRET_KEY"] = b'o5Dg987*&G^@(E&FW)}'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
app.config["SESSION_TYPE"] = 'sqlalchemy'
app.config["SESSION_SQLALCHEMY"] = db
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_SECURE"] = True  # browser to send a cookie only over protected HTTPS connection
app.config["SESSION_COOKIE_HTTPONLY"] = True  # browser to hide cookie content from javscript code
app.config[
    "SESSION_COOKIE_SAMESITE"] = 'Lax'  # Do not allow sending cookies from another sites when doing request other than GET method (to prevent CSRF)
sess = Session(app)


# SQL Tables
class Users(db.Model):
    email = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    password_expiry = db.Column(db.DateTime)
    password_hist = db.Column(db.String)
    clearance = db.Column(db.String, nullable=False)
    department = db.Column(db.String)
    workgroup = db.Column(db.String)
    status = db.Column(db.String)
    role = db.Column(db.String, nullable=False)
    last_active_date = db.Column(db.DateTime)

class Files(db.Model):
    id = db.Column(db.String, default=lambda:uuid.uuid4().hex,primary_key=True)
    filename = db.Column(db.String(50), nullable=False)
    filetype = db.Column(db.String(50))
    data = db.Column(db.LargeBinary, nullable=False)
    owner = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String, nullable=False)
    classification = db.Column(db.Integer, nullable=False)
    size = db.Column(db.String)
    last_accessed = db.Column(db.DateTime)
    shared_with = db.Column(db.String)

@app.route('/', methods=['GET', 'POST'])
def home():
    # try:
    #     if not session['user']:
    #         return redirect(url_for('login'))
    # except KeyError:
    #     return redirect(url_for('login'))
    try:
        if session['user']:
            check_expire(check_expiry())
            files = Files.query.all()
            my_files = []
            shared_files = []
            recycled_files = []
            for file in files:
                if session['user'].email == file.owner and file.status == 'active':
                    my_files.append(file)
                elif session['user'].email in file.shared_with and file.status == 'active':
                    shared_files.append(file)
                elif session['user'].email == file.owner and file.status == 'deleted':
                    recycled_files.append(file)
            uploadform = UploadForm(request.form)
            batch_uploadform = BatchUploadForm(request.form)
            return render_template('home.html', my_files=my_files, shared_files=shared_files,
                                   recycled_files=recycled_files, uploadform=uploadform,
                                   batch_uploadform=batch_uploadform)
    except KeyError:
        return redirect(url_for('login'))


# Login system
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = Users.query.filter_by(email=form.Email.data).first()
        try:
            if session['attempt'] < 5:
                session['attempt'] += 1
            elif session['attempt'] == 5:
                if user:
                    user.status = 'Disabled'
                    db.session.commit()
                return redirect(url_for('disabled'))
        except KeyError:
            session['attempt'] = 1
        if user:
            if user.role == "Admin":
                # face = authFace()
                # if face == 'WEN HAO':
                session["user"] = user
                flash(f'{session["user"].name} has logged in!', 'success')
                user.last_active_date = datetime.today().date()
                db.session.commit()
                session.pop('attempt')
                return redirect(url_for('home'))
            elif user.password == form.Password.data and user.status == "Active":
                secret_key = pyotp.random_base32()
                totp = pyotp.TOTP(secret_key)
                session['totp'] = totp
                qr_link = totp.provisioning_uri(user.name, issuer_name='Box-Box')
                img = qrcode.make(qr_link)
                img.save('static\img\qrcode.png')
                return redirect(url_for('login_2fa', user=user.email))
            elif user.status == "Disabled":
                return redirect(url_for('disable'))
        flash(f'Incorrect username or password,you have {5 - session["attempt"]} tries left', 'danger')
    return render_template('login.html', form=form)


@app.route('/login/2fa/<user>', methods=['GET', 'POST'])
def login_2fa(user):
    form = OTPForm(request.form)
    user = Users.query.filter_by(email=user).first()
    print(session['totp'].now())
    return render_template('login_2fa.html', form=form, user=user.email)


@app.route('/login_2fa/<user>', methods=['GET', 'POST'])
def login_2fa_form(user):
    form = OTPForm(request.form)
    user = Users.query.filter_by(email=user).first()
    if request.method == "POST" and form.validate():
        if session['totp'].verify(form.OTP.data):
            session["user"] = user
            user.last_active_date = datetime.today().date()
            db.session.commit()
            flash(f'{session["user"].name} has logged in!', 'success')
            session.pop('attempt')
            return redirect(url_for('home'))
        else:
            flash(f'Incorrect OTP code', 'danger')
            return redirect(url_for('login'))


@app.route('/change_password', methods=["GET", "POST"])
def change_password():
    form = ChangePasswordForm(request.form)
    if request.method == "POST" and form.validate():
        user = session['user']
        user = Users.query.filter_by(email=user.email).first()
        # if check_expiry() > 87:
        #     flash("You can only change passwords every 3 days", "info")
        #     return redirect(url_for('home'))
        password_hist = user.password_hist
        password = password_hist.split()
        new_pass = form.Password.data
        if new_pass not in password:
            password.append(new_pass)
            if len(password) > 5:
                password.pop(0)
            user.password = form.Password.data
            today = datetime.today().date()
            user.password_hist = " ".join(item for item in password)
            user.password_expiry = today + timedelta(days=90)
            db.session.commit()
            flash('Password changed successfully, please re-login', 'success')
            logout()
            return redirect(url_for('home'))
        else:
            flash('Past 5 passwords cannot be reused!', 'danger')
            return redirect(url_for('change_password'))
    else:
        return render_template('change_password.html', form=form)


def check_expiry():
    today = datetime.today().date()
    expire_date = session['user'].password_expiry.date()
    expire_time = (expire_date - today).days
    return expire_time


def check_expire(expire_time):
    if expire_time <= 0:
        flash(f'Your password has expired,please change to continue!', 'danger')
        return redirect(url_for('change_password'))
    elif expire_time <= 15:
        flash(f'Your password will expire in {expire_time} days! Please change soon!', 'danger')
        return redirect(url_for('home'))


@app.route('/disabled')
def disabled():
    return render_template('disable.html')


# Session Time out
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=300)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# File Related
@app.route('/uploads', methods=['POST'])
def upload():
    form = UploadForm(request.form)
    if request.method == 'POST' and form.validate():
        file = request.files['File']
        filetype = magic.from_buffer(file.read(2048))
        file.seek(0, os.SEEK_END)  # Get file size
        file_length = file.tell()
        filesize = naturalsize(file_length)
        fileItem = Files(filename=file.filename, data=file.read(), owner=session["user"].email, status="active",
                         filetype=filetype, size=filesize, last_accessed=datetime.now(),
                         shared_with='',
                         classification=form.Class.data)
        db.session.add(fileItem)
        db.session.commit()
        flash(f'{file.filename} has been saved!', 'success')
        return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route('/batch_uploads', methods=['POST'])
def upload_batch():
    if request.method == 'POST':
        file = request.files.getlist('Files')
        print(file)
        for f in file:
            filetype = magic.from_buffer(f.read(2048))
            f.seek(0, os.SEEK_END)  # Get file size
            file_length = f.tell()
            filesize = naturalsize(file_length)
            fileItem = Files(filename=f.filename, data=f.read(), owner=session["user"].email, status="active",
                             filetype=filetype, size=filesize, last_accessed=datetime.now(),
                             shared_with='',
                             classification='Unclassified')
            db.session.add(fileItem)
            db.session.commit()
        flash(f'{len(file)} files has been saved!', 'success')
        return redirect(url_for('home'))
    return redirect(url_for('home'))

@app.route('/share/<id>', methods=['POST', 'GET'])
def share(id):
    form = ShareForm(request.form)
    if request.method == 'POST' and form.validate():
        file = Files.query.filter_by(id=id).first()
        user = Users.query.filter_by(email=form.Email.data).first()
        access_type = form.Access_Type.data
        if file and user:
            if file.shared_with == '':
                new_user = user.email
                access_control_user = {}
                access_control_user[new_user] = access_type
                access_control_user = json.dumps(access_control_user) #change from dict to str
                file.shared_with = access_control_user
                db.session.commit()
                flash(f'{file.filename} has been shared to {user.name}!', 'success')
            else:
                new_user = user.email
                access_control_user = file.shared_with
                access_control_user = json.loads(access_control_user) #change from str to dict
                access_control_user[new_user] = access_type
                access_control_user = json.dumps(access_control_user) #change from dict to str
                file.shared_with = access_control_user
                db.session.commit()
                flash(f'{file.filename} has been shared to {user.name}!', 'success')
            if access_type == 'Owner':
                new_user = user.email
                file.owner = new_user
                access_control_user = file.shared_with
                access_control_user = json.loads(access_control_user)
                if new_user in access_control_user: # to remove the new owner email from the file.shared_with
                    access_control_user.pop(new_user)
                if session['user'].email not in access_control_user:
                    access_control_user[session['user'].email] = 'Editor'
                access_control_user = json.dumps(access_control_user)
                file.shared_with = access_control_user
                db.session.commit()
        else:
            flash('Invalid user email or file ID, please try again!','danger')
        return redirect(url_for('home'))
    return render_template('share.html',form=form)

@app.route('/sharing_details/<id>',methods=['POST','GET'])
def sharing_details(id):
    try:
        if not session['user']:
            return redirect(url_for('login'))
    except KeyError:
        flash('Please login into your account!','danger')
        return redirect((url_for('login')))

    file = Files.query.filter_by(id=id).first()
    sharing_detail = file.shared_with
    sharing_detail = json.loads(sharing_detail)
    for user in sharing_detail:
        print(user,sharing_detail[user])
    return redirect(url_for('home'))

@app.route('/downloads/<id>', methods=['POST', 'GET'])
def download(id):
    try:
        if not session['user']:
            return redirect(url_for('login'))
    except KeyError:
        flash('Please login into your account!','danger')
        return redirect((url_for('login')))
    file = Files.query.filter_by(id=id).first()
    try:
        if file.owner != session['user'].email and session['user'].email not in file.shared_with: #User is not owner and the file is not shared with him
                flash('Access denied 1','danger')
                return redirect(url_for('home'))
        elif file.owner != session['user'] and session['user'].email in file.shared_with: # user is not owner but file is shared with him
            file.last_accessed = datetime.now()
            db.session.commit()
            return send_file(BytesIO(file.data), as_attachment=True, attachment_filename=file.filename)
        else:# user is the owner
            file.last_accessed = datetime.now()
            db.session.commit()
            return send_file(BytesIO(file.data), as_attachment=True, attachment_filename=file.filename)
    except AttributeError:
        flash('Access denied 123','danger')
        return redirect(url_for('home'))

@app.route('/remove/<id>', methods=['POST', 'GET'])
def remove(id):
    try:
        if not session['user']:
            return redirect(url_for('login'))
    except KeyError:
        flash('Please login into your account!', 'danger')
        return redirect(url_for('login'))
    file = Files.query.filter_by(id=id).first()
    try:
        if file.owner != session['user'].email and session['user'].email not in file.shared_with: #user not file owner and file not shared with
            flash('Access denied 1','danger')
            return redirect(url_for('home'))
        elif file.owner != session['user'].email and session['user'].email in file.shared_with: #user not file owner but file is being shared with him
            delete_file(file)
            return redirect(url_for('home'))
        else: # user is file owner
            delete_file(file)
            return redirect(url_for('home'))
    except AttributeError: #file does not exist
        flash('Access denied','danger')
        return redirect(url_for('home'))

def delete_file(file):
    if file.status == "active":
        file.status = "deleted"
        flash(f'{file.filename} has been moved to Recycle Bin!', 'success')
    else:
        db.session.delete(file)
        flash(f'{file.filename} has been permanently removed!', 'success')
    db.session.commit()

@app.route('/edit_file/<id>', methods=['POST', 'GET'])
def edit_file(id):
    try:
        if not session['user']:
            return redirect(url_for('login'))
    except KeyError:
        flash('Please login into your account!', 'danger')
        return redirect(url_for('login'))
    try:
        file = Files.query.filter_by(id=id).first()
        if file.owner != session['user'].email and session['user'].email not in file.shared_with:#user is not file owner and file is not being shared with him
            flash("Access denied",'danger')
            return redirect(url_for('home'))
        if session['user'].email == file.owner:
            form = EditForm(request.form)
            if request.method == 'POST' and form.validate():
                file.filename = form.FileName.data
                file.classification = form.Class.data
                file.last_accessed = datetime.now()
                db.session.commit()
                flash('Changes have been made to the file', 'success')
                return redirect(url_for('home'))
            form.Class.data = file.classification
            return render_template('editfile.html', form=form, file=file)
        if session['user'].email in file.shared_with:#file is being shared with user then can edit
            access_control_user = file.shared_with
            access_control_user = json.loads(access_control_user)
            for users in access_control_user:
                if users == session['user'].email:
                    access_type = access_control_user[users]
                    break
            if access_type == 'Download':
                flash('You are not allowed to edit the file!','danger')
                return redirect(url_for('home'))
            elif access_type == 'Editor':
                form = EditForm(request.form)
                if request.method == 'POST' and form.validate():
                    file.filename = form.FileName.data
                    file.classification = form.Class.data
                    file.last_accessed = datetime.now()
                    db.session.commit()
                    flash('Changes have been made to the file', 'success')
                    return redirect(url_for('home'))
                form.Class.data = file.classification
                return render_template('editfile.html', form=form, file=file)
    except AttributeError:
        flash("Access denied", 'danger')
        return redirect(url_for('home'))

@app.route('/restore/<id>', methods=['POST', 'GET'])
def restore(id):
    try:
        if not session['user']:
            return redirect(url_for('login'))
    except KeyError:
        flash('Please login into your account!', 'danger')
        return redirect(url_for('login'))

    file = Files.query.filter_by(id=id).first()
    try:
        if file.owner != session['user'].email and session['user'].email not in file.shared_with:
            flash("Access denied",'danger')
            return redirect(url_for('home'))
        if file.owner == session['user'].email:
            file.status = "active"
            file.last_accessed = datetime.now()
            flash(f'{file.filename} has been restored!', 'success')
            db.session.commit()
            return redirect(url_for('home'))
    except AttributeError:
        flash('Access denied','danger')
        return redirect(url_for('home'))


if __name__ == '__main__':
    # db.create_all()
    # user_1 = Users(email='123@gmail.com', name='John Doe', password='password', clearance="Top Secret",
    #                workgroup='boxbox', role="User",password_hist='password',password_expiry = datetime.today().date() + timedelta(days=90),
    #                status="Active")
    # user_2 = Users(email='456@gmail.com', name='Jane Soh', password='password', clearance="Top Secret",
    #                workgroup='boxbox', role="User",password_hist='password',password_expiry = datetime.today().date() + timedelta(days=90),
    #                status="Active")
    # user_3 = Users(email='1234@gmail.com', name='Max Lim', password='password', clearance="Secret",
    #                workgroup='boxbox', role="User",password_hist='password',password_expiry = datetime.today().date() + timedelta(days=90),
    #                status="Active")
    # db.session.add(user_1)
    # db.session.add(user_2)
    # db.session.add(user_3)
    # db.session.commit()
    app.run(debug=True)
