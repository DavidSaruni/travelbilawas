from flask import Flask,render_template,request,redirect,flash,url_for,session
from flask_mysqldb import MySQL
from flask_mail import Mail,Message
from random import *
import re
import bcrypt
import base64
import time
import secrets

app=Flask(__name__)




app.secret_key='booking'
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='bus_booking'


mysql=MySQL(app)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'bilawastravel@gmail.com'
app.config['MAIL_PASSWORD'] = 'plgqeysfehioxcmg'

mail = Mail(app)




@app.route('/home')
def home():
    return render_template('home/page-404.html')


@app.route('/register',methods=['POST','GET'])
def register():
    if  'username' in session:
        return redirect(url_for('dashboard'))
    else:
        if request.method=='POST':
            username=request.form['username']
            email=request.form['email']
            password=request.form['password']
            confirm=request.form['confirm']
            choice=request.form['user']
            phone=request.form['phone']
            is_verified=0
            otp=str(secrets.randbelow(1000000)).zfill(6)
            otp_secret=otp
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email=%s",(email,))
            user = cur.fetchone()
            cur.execute("SELECT * FROM users WHERE username=%s",(username,))
            data = cur.fetchone()
            if data:
                flash('Username already exists','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif user:
                flash('Email already exists','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif username==''or email==''or password==''or phone=='' or confirm=='' or choice=='':
                flash('All fields are required','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif password!=confirm:
                flash('Passwords do not match','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif len(password)<8:
                flash('Password should be more than 8 characters','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif not re.search("[a-z]",password):
                flash('Password should contain small letters','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            elif not re.search("[A-Z]", password):
                flash('Password should contain capital letters','danger')
                return render_template('accounts/register.html',phone=phone,username=username,email=email,password=password,confirm=confirm)
            else:
                send_verification(email, otp)
                flash(f"Verification code sent to {email}",'success')
                hashed_password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cur=mysql.connection.cursor()
                verification_sent_at = int(time.time())
                cur.execute("INSERT INTO users(username, email, password, role, otp_secret, is_verified, verification_sent_at,phone) VALUES(%s, %s, %s, %s, %s, %s, %s,%s)", (username, email, hashed_password, choice, otp_secret, is_verified, verification_sent_at,phone))
                mysql.connection.commit()
                cur.close()
                return redirect(url_for('verify'))
    return render_template('accounts/register.html')


def send_verification(email, otp):
    subject = 'Email Verification code'
    body = f'Your verification code is: {otp}'

    msg = Message(subject=subject, sender='bilawastravel@gmail.com', recipients=[email], body=body)

    try:
        mail.send(msg)

    except Exception as e:
        print("Error sending email:", e)





@app.route('/verify', methods=['POST', 'GET'])
def verify():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    else:
        if request.method == 'POST':
            user_otp = request.form['otp']
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE otp_secret=%s", (user_otp,))
            user = cur.fetchone()

            if user is not None:
                is_verified = int(user[6])  
                if is_verified == 1:
                    flash("Email has already been verified. You can now login.", 'info')
                    return redirect(url_for('login'))
                else:
                    verification_sent_at = user[7] 
                    current_timestamp = int(time.time())
                    expiration_time =24 * 60 * 60

                    if current_timestamp - verification_sent_at > expiration_time:
                        cur.execute("DELETE FROM users WHERE id=%s", (user[0],))  
                        mysql.connection.commit()
                        cur.close()
                        flash("Verification email has expired. Account  deleted.", 'danger')
                        return redirect(url_for('register'))

                    user_id = user[0]
                    is_verified = 1

                    cur.execute("UPDATE users SET is_verified=%s WHERE id=%s", (is_verified, user_id,))
                    mysql.connection.commit()
                    cur.close()

                    flash("Email verified successfully now can login.", 'success')
                    return redirect(url_for('login'))
            else:
                flash("You have entered an invalid code. Please try again.", 'danger')
                return redirect(url_for('verify'))

    return render_template('home/email_verify.html')



@app.route('/',methods=['POST','GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        if request.method=='POST':
            username=request.form['username']
            password=request.form['password']
            
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username=%s ",(username,))
            mysql.connection.commit()
            user=cur.fetchone()
            cur.close()
            if user is not None:
                is_verified = int(user[6])
                if is_verified==1:
                    hashed_password=user[3].encode('utf-8')
                    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                        session['loggedin']=True
                        session['username']=user[1]
                        session['user_id']=user[0]
                        session['email']=user[2]
                        session['role'] = user[4] 
                        # flash(f"You are logged in as {username} ",'success')
                        if session['role']=="Admin":
                            return redirect(url_for('dashboard'))
                        return redirect(url_for('explore'))
                    else:
                        flash('Incorrect password','danger')
                        return render_template('accounts/login.html',username=username,password=password)
                else:
                    flash('Please verify your email before logging in.','info')
                    return redirect(url_for('verify'))
                
            else:
                flash('You have entered wrong username','danger')
                return render_template('accounts/login.html',username=username,password=password)
    return render_template('accounts/login.html')


@app.route('/forgot',methods=['POST','GET'])
def forgot():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        if request.method=='POST':
            email=request.form['email']
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email=%s",(email,))
            result=cur.fetchone()
            if result:
                token=secrets.token_hex(32)
                reset_link=url_for('reset',token=token,_external=True)
                msg=Message(subject='Password Reset Request',sender='bilawastravel@gmail.com',recipients=[email])
                msg.body=f'Click the following link to reset your password:{reset_link}'
                mail.send(msg)
                reset_sent_at = int(time.time())
                cur=mysql.connection.cursor()
                cur.execute("UPDATE users SET token=%s, reset_sent_at=%s WHERE email=%s",(token,reset_sent_at,email))
                mysql.connection.commit()
                cur.close()
                flash('Reset link has been send to your email','success')
                return redirect(url_for('forgot'))
            else:
                flash("We can't find your email in our system",'danger')
                return redirect(url_for('forgot'))
        return render_template('home/forgot.html')

@app.route('/reset',methods=['POST','GET'])
def reset():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        if request.method=='POST':
            password=request.form['password']
            re_password=request.form['confirm']
            token = request.args.get('token') 
            
            if password != re_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('reset', token=token))
            elif len(password) < 8:
                flash('Weak password! Password should be at least 8 characters long', 'danger')
                return redirect(url_for('reset', token=token))
            elif not re.search("[A-Z]", password):
                flash('Password should include a capital letter', 'danger')
                return redirect(url_for('reset', token=token))
            elif not re.search("[a-z]", password):
                flash('Password should include a small letter', 'danger')
                return redirect(url_for('reset', token=token))
            else:
                cur = mysql.connection.cursor()
                cur.execute("SELECT * FROM users WHERE token=%s", (token,))
                result = cur.fetchone()
                if result:
                    email = result[2]
                    reset_sent_at = result[9]

                
                    current_timestamp = int(time.time())
                    expiration_time = 15 * 60  
                    if current_timestamp - reset_sent_at > expiration_time:
                        flash('The token has expired token', 'danger')
                        return redirect(url_for('forgot'))

                    hashed_password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    cur.execute("UPDATE users SET password=%s, token='token' WHERE email=%s", (hashed_password, email))
                    mysql.connection.commit()
                    cur.close()

                    flash('Password reset successfully', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid or expired token', 'danger')
                    return redirect(url_for('forgot'))
    return render_template('home/reset.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        cur=mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id=%s",(user_id,))
        user=cur.fetchone()[0]
        
        cur.execute("SELECT * FROM trip")
        result=cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM trip")
        trip_count=cur.fetchone()[0]
        cur.execute("SELECT * FROM trip WHERE user_id=%s",(user_id,))
        user_result=cur.fetchall()

        cur.execute("SELECT * FROM events")
        results=cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM events")
        event_count=cur.fetchone()[0]
        cur.execute("SELECT * FROM events WHERE user_id=%s",(user_id,))
        user_results=cur.fetchall()



        cur.execute("SELECT * FROM students")
        students=cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM students")
        student_count=cur.fetchone()[0]
        cur.execute("SELECT * FROM students WHERE user_id=%s",(user_id,))
        user_students=cur.fetchall()

        cur.execute("SELECT * FROM parcel")
        parcel=cur.fetchall()
        modified_parcel = []
        for item in parcel:
            image_data = item[5]
            image_data_base64 = base64.b64encode(image_data).decode('utf-8')
            modified_items = list(item)
            modified_items[5] = image_data_base64
            modified_parcel.append(modified_items)
        cur.execute("SELECT COUNT(*) FROM parcel")
        parcel_count=cur.fetchone()[0]
        cur.execute("SELECT * FROM parcel WHERE user_id=%s",(user_id,))
        user_parcel=cur.fetchall()
        modified_data = []
        for item in user_parcel:
            image_data = item[5]
            image_data_base64 = base64.b64encode(image_data).decode('utf-8')
            modified_item = list(item)
            modified_item[5] = image_data_base64
            modified_data.append(modified_item)
            

        mysql.connection.commit()
        cur.close()
        total_count=trip_count+event_count+student_count+parcel_count
        return render_template('home/index.html',user=user,result=result,user_result=user_result,results=results,user_results=user_results,students=students,user_students=user_students,parcel=modified_parcel,user_parcel=modified_data,total_count=total_count,per_cent=(total_count/50)*100)
        
    return render_template('home/index.html')


@app.route('/trip',methods=['POST','GET'])
def trip():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        username=session['username']
        cur=mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id=%s",(user_id,))
        user=cur.fetchone()[0]
        if request.method=='POST':
            pick_up = request.form['Location']
            destination = request.form['destination']
            seats = int(request.form['seats'])
            date = request.form['TravelDate']
            time = request.form['Time']
            amount = int(request.form['amount'])
            status="Pending"
            if user=='Admin':
                flash('Admin is not allowed to book in this page','info')
                return redirect(url_for('trip'))
            if pick_up==''or destination==''or date==''  or seats=='' or amount=='':
                flash('All fields are required','danger')
                return render_template('home/solo-travel.html',location=location,constituency=constituency,town=town,destination=destination,date=date,seats=seats,amount=amount)
            cur=mysql.connection.cursor()
            cur.execute("INSERT INTO trip(user_id,username,pick_up,destination,date,seats,time,amount,status)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(user_id,username,pick_up,destination,date,seats,time,amount,status))
            mysql.connection.commit()
            cur.close()
            # flash('Please finish booking by paying','info')
            return redirect(url_for('dashboard'))
    return render_template('home/solo-travel.html')

@app.route('/event',methods=['POST','GET'])
def event():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        username=session['username']
        cur=mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id=%s",(user_id,))
        user=cur.fetchone()[0]
        if request.method=='POST':
            event_type = request.form['event_type']
            location = request.form['location']
            destination = request.form['destination']
            constituency= request.form['constituency']
            town =request.form['town']
            number_pass = int(request.form['matatu'])
            date = request.form['date']
            time = request.form['time']
            amount = int(request.form['amount'])
            status="Pending"
            if user=='Admin':
                flash('Admin is not allowed to book in this page','info')
                return redirect(url_for('trip'))
            if location==''or destination==''or constituency=='' or town=='' or date==''or number_pass=='' or event_type=='' or amount=='':
                flash('All fields are required','danger')
                return render_template('home/event-travel.html',event_type=event_type,town=town,constituency=constituency,location=location,destination=destination,date=date,matatu=matatu,amount=amount)
            cur=mysql.connection.cursor()
            cur.execute("INSERT INTO events(user_id,username,location,destination,date,time,number_pass,amount,event_type,constituency,town,status)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(user_id,username,location,destination,date,time,number_pass,amount,event_type,constituency,town,status))
            mysql.connection.commit()
            cur.close()
            # flash('Please finish booking by paying','info')
            return redirect(url_for('dashboard'))
    return render_template('home/event-travel.html')


@app.route('/student', methods=['POST', 'GET'])
def student():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id = session['user_id']
        username = session['username']
        cur = mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()[0]
        if request.method == 'POST':
            pick_up = request.form['location']
            destination = request.form['destination']
            seats = int(request.form['seats'])
            date = request.form['date']
            time = request.form['time']
            amount = int(request.form['amount'])
            status="Pending"
            if user == 'Admin':
                flash('Admin is not allowed to book on this page', 'info')
                return redirect(url_for('trip'))
            if pick_up == '' or destination=='' or date == '' or time=='' or seats == '' or amount == '':
                flash('All fields are required', 'danger')
                return render_template('home/student-travel.html', students=students, institution=institution,
                                       date=date, matatu=matatu, amount=amount)
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO students(user_id, username,pick_up,date,destination,time,seats,amount,status) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s,%s)",
                        (user_id, username,pick_up,date,destination,time,seats,amount,status))
            mysql.connection.commit()
            cur.close()
            # flash('Please finish booking by paying', 'info')
            return redirect(url_for('dashboard'))

        
        num_additional_destinations = request.args.get('num_additional_destinations', type=int)
        if num_additional_destinations is None:
            num_additional_destinations = 0

        return render_template('home/student-travel.html', destinations=[''], num_additional_destinations=num_additional_destinations)


@app.route('/parcel',methods=['POST','GET'])
def parcel():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        username=session['username']
        cur=mysql.connection.cursor()
        cur.execute("SELECT role FROM users WHERE id=%s",(user_id,))
        user=cur.fetchone()[0]
        if request.method=='POST':
            pick_up = request.form['location']
            destination = request.form['destination']
            photo = request.files['photo'].read()
            amount = int(request.form['amount'])
            status="Pending"
            if user=='Admin':
                flash('Admin is not allowed to book in this page','info')
                return redirect(url_for('trip'))
            if pick_up==''or destination==''or photo==''or amount=='':
                flash('All fields are required','danger')
                return render_template('home/parcel-transport.html',location=location,destination=destination,photo=photo,amount=amount)
            cur=mysql.connection.cursor()
            cur.execute("INSERT INTO parcel(user_id,username,pick_up,destination,photo,amount,status)VALUES(%s,%s,%s,%s,%s,%s,%s)",(user_id,username,pick_up,destination,photo,amount,status))
            mysql.connection.commit()
            cur.close()
            # flash('Please finish booking by paying','info')
            return redirect(url_for('dashboard'))
    return render_template('home/parcel-transport.html')



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        username=session['username']
        if request.method == 'POST':
            fname = request.form['fname']
            lname = request.form['lname']
            address = request.form['address']
            bio = request.form['bio']
            photo = request.files['photo'].read()
            phone=request.form['phone']

            
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
            record=cur.fetchone()
            if record is not None:
                # Update the existing user profile
                cur=mysql.connection.cursor()
                cur.execute("UPDATE profile SET fname=%s,lname=%s,address=%s,bio=%s,photo=%s,phone=%s WHERE user_id=%s",(fname,lname,address,bio,photo,phone,user_id,))
                mysql.connection.commit()
                cur.close()
            else:
                # Create a new user profile
                cur=mysql.connection.cursor()
                cur.execute("INSERT INTO profile(user_id,username,fname,lname,address,bio,photo,phone)VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",(user_id,username,fname,lname,address,bio,photo,phone))
                mysql.connection.commit()
                cur.close()

        # Retrieve the updated or newly created profile record
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
        data=cur.fetchone()
        if data:
            image=data[7]
            image_base64=base64.b64encode(image).decode('utf-8')
            if data[7]:
                return render_template('home/profile.html', data=data,image_base64=image_base64)
    return render_template('home/profile.html', data=data)






@app.route('/users')
def users():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM users")
        data=cur.fetchall()
        
        cur.execute("SELECT role FROM users WHERE id=%s",(user_id,))
        user=cur.fetchone()[0]
        mysql.connection.commit()
        cur.close()


        return render_template('users.html',users=data,user=user)
    return render_template('users.html')


@app.route('/pay/<id>/<table>',methods=['POST','GET'])
def Payment(id,table):
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    else:
        user_id=session['user_id']
        if table=="trip":
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM trip WHERE id=%s",(id,))
            record=cur.fetchone()
            cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
            data=cur.fetchone()
            mysql.connection.commit()
            cur.close()
            return render_template('home/pay.html',record=record,data=data,table="trip") 
            
        elif table=="events":
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM events WHERE id=%s",(id,))
            record=cur.fetchone()
            cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
            data=cur.fetchone()
            mysql.connection.commit()
            cur.close()
            return render_template('home/pay.html',record=record,data=data,table="events") 
        elif table=="students":
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM students WHERE id=%s",(id,))
            record=cur.fetchone()
            cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
            data=cur.fetchone()
            mysql.connection.commit()
            cur.close()
            return render_template('home/pay.html',record=record,data=data,table="students") 
        elif table=="parcel":
            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM parcel WHERE id=%s",(id,))
            record=cur.fetchone()
            cur.execute("SELECT * FROM profile WHERE user_id=%s",(user_id,))
            data=cur.fetchone()
            mysql.connection.commit()
            cur.close()
            return render_template('home/pay.html',record=record,data=data,table="parcel") 




@app.route('/explore')
def explore():
    if 'user_id' and 'role' and 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home/explore.html')


@app.route('/status/<id>/<table>',methods=['POST','GET'])
def Status(id,table):
    if request.method == 'POST':
        status = request.form['status']
        
        if table=="trip":
            cur=mysql.connection.cursor()
            cur.execute("UPDATE trip SET status=%s WHERE id=%s",(status,id,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('dashboard'))
        elif table=="students":
            cur=mysql.connection.cursor()
            cur.execute("UPDATE students SET status=%s WHERE id=%s",(status,id,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('dashboard'))
        
        elif table=="events":
            cur=mysql.connection.cursor()
            cur.execute("UPDATE events SET status=%s WHERE id=%s",(status,id,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('dashboard'))

        elif table=="parcel":
            cur=mysql.connection.cursor()
            cur.execute("UPDATE parcel SET status=%s WHERE id=%s",(status,id,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('dashboard'))
    return render_template('home/status.html')



@app.route('/logout')
def logout():
    if 'user_id' or 'role' or 'username' in session:
        session.pop('loggedin',None)
        session.pop('username',None)
        session.pop('user_id',None)
        session.pop('role',None)
        session.pop('email',None)
        flash('You have been logged out','warning')
    return redirect(url_for('login'))


if __name__=='__main__':
    app.run(debug=True)



