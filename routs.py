from app import app
from flask import render_template, request, redirect, url_for, flash, session
from flask import request as flask_request
from models import db, User, Services, Worker, Job, Request
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask import jsonify
from sqlalchemy import func


# ------------ Authentication Pages ---------------------

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return inner


# ---------------- Login Page --------------------
@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_post():
    role = request.form.get("role")
    username = request.form.get('username')
    password = request.form.get("password")
    if not username or not password:
        flash("Fill all fields")
        return redirect(url_for("login"))

    if role == "user":
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Username doesn't exist")
            return redirect(url_for("login"))
        if not check_password_hash(user.passhash, password):
            flash("Incorrect Password")
            return redirect(url_for("login"))

        session['user_id'] = user.id
        session['role'] = 'user'
        flash("Login Successful!")
        if user.is_admin:
            return redirect(url_for("admin"))
        return redirect(url_for("user_homepage"))

    if role == "service_professional":
        worker = Worker.query.filter_by(username=username).first()
        if not worker:
            flash("Username doesn't exist")
            return redirect(url_for("login"))
        if not check_password_hash(worker.passhash, password):
            flash("Incorrect Password")
            return redirect(url_for("login"))

        session['user_id'] = worker.id
        session['role'] = 'worker'
        return redirect(url_for("worker_homepage"))
    
# Logout
@app.route("/logout")
@auth_required
def logout():
    session.pop("user_id")
    flash("Successfully Logged out!!")
    return redirect(url_for("login"))


# User Register

@app.route("/user-register")
def user_register():
    return render_template("user-register.html")

@app.route("/user-registration", methods=["POST"])
def user_registration_post():
    username = request.form.get("username")
    name = request.form.get("name")
    password = request.form.get("password")
    cpassword = request.form.get("cpassword")
    contact = request.form.get("contact")
    address = request.form.get("address")
    pin = request.form.get("pin")

    if not username or not name or not password or not cpassword or not contact or not address or not pin:
        flash("Please fill out all the fields!!")
        return redirect(url_for("user_register"))

    if password != cpassword:
        flash("Passwords don't match!!")
        return redirect(url_for("user_register"))

    user = User.query.filter_by(username=username).first()
    if user:
        flash("Username already exists!!")
        return redirect(url_for("user_register"))

    password_hash = generate_password_hash(password)
    new_user = User(username=username, name=name, passhash=password_hash, contact=contact, address=address, pin=pin)
    db.session.add(new_user)
    db.session.commit()
    flash("Registration successful! Please log in.")
    return redirect(url_for("login"))

# Professional Register

@app.route("/professional-register")
def professional_register():
    services = Services.query.all()
    return render_template("worker-register.html", services=services)

@app.route("/professional-register", methods=["POST"])
def professional_register_post():
    username = request.form.get("username")
    name = request.form.get("name")
    password = request.form.get("password")
    cpassword = request.form.get("cpassword")
    age = request.form.get("age")
    service_id = request.form.get("service")
    experience = request.form.get("experience")
    contact = request.form.get("contact")
    email = request.form.get("email")
    address = request.form.get("address")
    pin = request.form.get("pin")

    if not all([username, name, password, cpassword, age, service_id, experience, contact, email, address, pin]):
        flash("Enter all fields")
        return redirect(url_for("professional_register"))

    if password != cpassword:
        flash("Passwords do not match")
        return redirect(url_for("professional_register"))

    if Worker.query.filter_by(username=username).first():
        flash("Username already exists")
        return redirect(url_for("professional_register"))

    if Worker.query.filter_by(email=email).first():
        flash("Email already exists")
        return redirect(url_for("professional_register"))

    password_hash = generate_password_hash(password)

    service = Services.query.get(service_id)
    if not service:
        flash("Selected service does not exist")
        return redirect(url_for("professional_register"))

    new_worker = Worker(
        username=username, name=name, passhash=password_hash, age=age,
        service_id=service.id, experience=experience, contact=contact, email=email,
        address=address, pin=pin
    )
    db.session.add(new_worker)
    db.session.commit()

    flash("Registration successful! Please log in.")
    return redirect(url_for("login"))



# -----------------Profile Pages-----------------------------
@app.route("/profile")
@auth_required
def profile():
    if session['role'] == 'user':
        user = User.query.filter_by(id=session["user_id"]).first()
        return render_template("profile.html", user=user)
    if session['role'] == 'worker':
        user = Worker.query.filter_by(id=session["user_id"]).first()
        return render_template("profile.html", user=user)
    

@app.route("/edit_profile", methods=["GET"])
@auth_required
def edit_profile():
    role = session.get('role')
    user_id = session.get('user_id')

    if role == 'user':
        user = User.query.get(user_id)
        return render_template("edit-profile.html", user=user, role='user')
    elif role == 'worker':
        worker = Worker.query.get(user_id)
        return render_template("edit-profile.html", worker=worker, role='worker')
    else:
        flash("Unauthorized access", "danger")
        return redirect("/profile")

@app.route("/edit_profile", methods=["POST"])
@auth_required
def edit_profile_post():
    role = session.get('role')
    user_id = session.get('user_id')

    username = request.form.get('username')
    currpassword = request.form.get('currpassword')
    newpassword = request.form.get('newpassword')
    name = request.form.get('name')
    address = request.form.get('address')
    pin = request.form.get('pin')
    contact = request.form.get('contact')

    if role == 'worker':
        age = request.form.get('age')
        email = request.form.get('email')
        description = request.form.get('description')

    if role == 'user':
        user = User.query.get(user_id)

        if user:
            if currpassword and not check_password_hash(user.passhash, currpassword):
                flash("Current Password is Incorrect!", "danger")
                return redirect(url_for("edit_profile"))
            user.username = username
            user.passhash = generate_password_hash(newpassword)
            user.name = name
            user.address = address
            user.pin = pin
            user.contact = contact

            db.session.commit()
            flash("Profile updated successfully!", "success")
        else:
            flash("User not found", "danger")

    elif role == 'worker':
        worker = Worker.query.get(user_id)
        if worker:
            if currpassword and not check_password_hash(worker.passhash, currpassword):
                flash("Current Password is Incorrect!", "danger")
                return redirect(url_for("edit_profile"))

            worker.username = username
            worker.passhash = generate_password_hash(newpassword)
            worker.name = name
            worker.address = address
            worker.pin = pin
            worker.contact = contact
            worker.age = age
            worker.email = email
            worker.description = description

            db.session.commit()
            flash("Profile updated successfully!", "success")
        else:
            flash("Worker not found", "danger")

    return redirect("/profile")


#------------------ Root ROute -------------------

@app.route("/")
@auth_required
def index():
    return render_template("index.html")







# --------------------------------Admin Pages---------------------------

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))

        return func(*args, **kwargs)

    return inner


# Admin Homepage
@app.route("/admin")
@admin_required
def admin():
    services = Services.query.all()
    jobs = Job.query.all()
    return render_template("admin.html", services = services, jobs = jobs)


# Add New Service
@app.route("/services/add")
@admin_required
def add_service():
    return render_template("services/add_service.html")

@app.route("/services/add", methods = ["POST"])
@admin_required
def add_service_post():
    name = request.form.get('name')
    base_price = request.form.get('base_price')
    time_required = request.form.get('time_required')
    description = request.form.get('description')
    

    if not name:
        flash("Enter the Service name")
        return redirect(url_for("add_service"))
    
    service = Services(name = name, base_price=base_price, time_required = time_required, description = description)
    db.session.add(service)
    db.session.commit()

    flash("Service Added Successfully!!")
    return redirect(url_for("admin"))


# Show Services to Admin
@app.route('/services/<int:id>/')
@admin_required
def show_service(id):
    service = Services.query.get(id)
    workers = Worker.query.filter_by(service_id=service.id).all()  
    return render_template("services/show_service.html", service=service, workers=workers)



# Show all the workers in that particular service
@app.route('/services/<int:service_id>/worker/<int:worker_id>/show')
@admin_required
def show_worker(service_id, worker_id):
    worker = Worker.query.filter_by(service_id= service_id, id=worker_id).first()
    return render_template("workers/show_worker.html", worker = worker)


# Edit Worker by admin
@app.route('/services/<int:service_id>/worker/<int:worker_id>/edit')
@admin_required
def edit_worker(service_id, worker_id):
    worker = Worker.query.filter_by(service_id=service_id, id=worker_id).first()
    return render_template("workers/edit_worker.html", worker=worker)

@app.route('/services/<int:service_id>/worker/<int:worker_id>/edit', methods=["POST"])
@admin_required
def edit_worker_post(service_id, worker_id):
    worker = Worker.query.filter_by(service_id=service_id, id=worker_id).first()
    
    username = request.form.get('username')
    currpassword = request.form.get('currpassword')
    newpassword = request.form.get('newpassword')
    name = request.form.get('name')
    age = request.form.get('age')
    address = request.form.get('address')
    pin = request.form.get('pin')
    contact = request.form.get('contact')
    email = request.form.get('email')
    description = request.form.get('description')

    if currpassword and not check_password_hash(worker.passhash, currpassword):
        flash("Current password is incorrect!", "danger")
        return redirect(url_for("edit_worker", service_id=service_id, worker_id=worker_id))
    worker.username = username
    if newpassword:
        worker.passhash = generate_password_hash(newpassword)
    worker.name = name
    worker.age = age
    worker.address = address
    worker.pin = pin
    worker.contact = contact
    worker.email = email
    worker.description = description
    db.session.commit()
    flash("Worker details updated successfully!", "success")
    
    return redirect(url_for("admin"))

# Delete Worker
@app.route('/services/<int:service_id>/worker/<int:worker_id>/delete')
@admin_required
def delete_worker(service_id, worker_id):
    worker = Worker.query.filter_by(service_id= service_id, id=worker_id).first()
    if not worker:
        flash("Worker not found.")
        return redirect(url_for("admin"))
    return render_template("workers/delete_worker.html", worker=worker)

@app.route('/services/<int:service_id>/worker/<int:worker_id>/delete', methods=["POST"])
@admin_required
def delete_worker_post(service_id, worker_id):
    worker = Worker.query.filter_by(service_id= service_id, id=worker_id).first()
    if not worker:
        flash("Worker not found.")
        return redirect(url_for("admin"))
    db.session.delete(worker)
    db.session.commit()
    flash("Worker Deleted Successfully!!")
    return redirect(url_for("admin"))


#----- Editing the service ------------
@app.route('/services/<int:id>/edit')
@admin_required
def edit_service(id):
    service = Services.query.get(id)
    return render_template("services/edit_service.html", service= service)

@app.route('/services/<int:id>/edit', methods = ["POST"])
@admin_required
def edit_service_post(id):
    name = request.form.get("name")
    base_price = request.form.get("base_price")
    time_required = request.form.get("time_required")
    description = request.form.get("description")
    service = Services.query.get(id)
    service.name = name
    service.base_price = base_price
    service.time_required = time_required
    service.description = description

    db.session.commit()
    flash("Service Updated Successfully!!")
    return redirect(url_for("admin"))



# ----- Deleting the service -----
@app.route('/services/<int:id>/delete')
@admin_required
def delete_service(id):
    service = Services.query.get(id)
    if not service:
        flash("Service not found.")
        return redirect(url_for("admin"))
    return render_template("services/delete_service.html", service=service)

@app.route('/services/<int:id>/delete', methods=["POST"])
@admin_required
def delete_service_post(id):
    service = Services.query.get(id)
    if not service:
        flash("Service not found.")
        return redirect(url_for("admin"))
    db.session.delete(service)
    db.session.commit()
    flash("Service successfully deleted.")
    return redirect(url_for("admin"))



#------------Admin Jobs routes ---------------------
# Approve the jobs
@app.route('/approve_job/<int:job_id>', methods=['POST'])
@admin_required
def approve_job(job_id):
    job = Job.query.get(job_id) 
    
    if job:  
        job.approved = "True"
        db.session.commit()
        flash("Job approved successfully!", "success")
    else:
        flash("Job not found!", "danger")
    
    return redirect(url_for("admin"))  

# Reject the Jobs
@app.route('/reject_job/<int:job_id>', methods=['POST'])
@admin_required
def reject_job(job_id):
    job = Job.query.get(job_id) 
    
    if job:  
        job.approved = "Rejected"
        db.session.commit()
        flash("Job Rejected!", "success")
    else:
        flash("Job not found!", "danger")
    
    return redirect(url_for("admin"))  

# View Job
@app.route('/view_job/<int:job_id>')
@admin_required
def view_job(job_id):
    job = Job.query.get(job_id)
    return render_template("jobs/view_job.html", job=job)



# ---------- Admin Users Data -----------
@app.route("/admin_users")
@admin_required
def admin_users():
    search_query = request.args.get('search', '')
    if search_query:
        users = User.query.filter(User.username.like(f'%{search_query}%')).all()
    else:
        users = User.query.all()
    
    return render_template("admin/customers.html", users=users, search_query=search_query)

@app.route('/view_admin_user/<int:user_id>')
@admin_required
def view_admin_user(user_id):
    user = User.query.get(user_id)
    return render_template("admin/show_user.html", user=user)


@app.route('/admin_user/<int:user_id>/delete')
@admin_required
def delete_admin_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        flash("User not found.")
        return redirect(url_for("admin"))
    return render_template("admin/delete_user.html", user=user)

@app.route('/admin_user/<int:user_id>/delete', methods=["POST"])
@admin_required
def delete_admin_user_post(user_id):
    user = User.query.filter_by(id = user_id).first()
    if not user:
        flash("user not found.")
        return redirect(url_for("admin"))
    db.session.delete(user)
    db.session.commit()
    flash("User Deleted Successfully!!")
    return redirect(url_for("admin"))




# ------------ Customer Charts -------------
@app.route('/admin/customer_data')
@admin_required
def customer_data():
    users = User.query.all()
    data = [{
        "username": user.username,
        "closed_requests_count": user.closed_requests_count(),
        "total_requests_count": len(user.requests)  # Total requests count
    } for user in users]
    return jsonify(data)

@app.route('/admin/customers_chart')
@admin_required
def admin_customers_chart():
    return render_template('admin/customer_data.html')

@app.route('/admin/services_chart')
@admin_required
def services_chart():
    # Service vs Count of Workers
    services = Services.query.all()
    services_data = [{"name": service.name, "workers_count": len(service.workers)} for service in services]

    # Job vs Base Price
    jobs = Job.query.all()
    jobs_data = [{"name": job.name, "base_price": job.bp} for job in jobs]

    # Job vs Rating
    job_ratings_data = [{"name": job.name, "rating": job.rating} for job in jobs if job.rating]

    return render_template(
        'admin/services_chart.html', 
        services_data=services_data, 
        jobs_data=jobs_data,
        job_ratings_data=job_ratings_data
    )

@admin_required
@app.route('/admin/services_jobs_data')
def services_jobs_data():
    services = Services.query.all()
    services_data = [{"name": service.name, "workers_count": len(service.workers)} for service in services]
    jobs = Job.query.all()
    jobs_data = [{"name": job.name, "base_price": job.bp} for job in jobs]

    job_ratings_data = [{"name": job.name, "rating": job.rating} for job in jobs]

    return jsonify({
        "services_data": services_data,
        "jobs_data": jobs_data,
        "job_ratings_data": job_ratings_data
    })



# ------------- Admin Worker Data -----------------
@app.route('/admin/workers_statistics')
@admin_required
def workers_statistics():
    return render_template('admin/worker_statistics.html')

@app.route('/admin/workers_data')
@admin_required
def workers_data():
    workers = Worker.query.all()

    top_workers_labels = []
    top_workers_ratings = []
    workers_labels = []
    closed_jobs_counts = []
    revenue = []

    for worker in workers:
        # Top 5 workers based on ratings
        if len(top_workers_labels) < 5:  
            top_workers_labels.append(worker.username)
            top_workers_ratings.append(worker.rating)

        # Workers and closed jobs
        workers_labels.append(worker.username)
        closed_jobs_counts.append(worker.closed_requests_count())

        # Revenue generated by each worker
        total_revenue = sum(job.bp for job in worker.jobs if job.approved == 'True')
        revenue.append(total_revenue)

    return jsonify({
        'top_workers_labels': top_workers_labels,
        'top_workers_ratings': top_workers_ratings,
        'workers_labels': workers_labels,
        'closed_jobs_counts': closed_jobs_counts,
        'revenue': revenue
    })


@app.route('/delete_job/<int:job_id>')
@admin_required
def delete_job_get(job_id):
    job = Job.query.get(job_id)
    return render_template("jobs/delete_job.html", job=job)

@app.route('/delete_job/<int:job_id>/confirm', methods=['POST'])
@admin_required
def delete_job(job_id):
    job = Job.query.get(job_id)
    if job:
        db.session.delete(job)
        db.session.commit()
    return redirect(url_for('admin'))


@app.route('/admin_workers')
@admin_required
def admin_workers():
    search_query = request.args.get('search', '')
    if search_query:
        workers = Worker.query.filter(
            (Worker.username.ilike(f'%{search_query}%')) |
            (Worker.name.ilike(f'%{search_query}%')) |
            (Worker.service.has(name=search_query))
        ).all()
    else:
        workers = Worker.query.all()
        
    return render_template("admin/workers.html", workers=workers, search_query=search_query)


# ---------------------------------------------End Of Admin Pages ---------------------------------------------------------





# ------------------------------------------------------ --Worker Pages -----------------------------------------

@app.route('/worker_homepage')
@auth_required
def worker_homepage():
    worker = Worker.query.filter_by(id=session["user_id"]).first()
    jobs = worker.jobs
   
    status_order = {'True': 0, 'False': 1, 'Rejected': 2}

    sorted_jobs = sorted(jobs, key=lambda job: status_order.get(job.approved, 3))
    
    requests = Request.query.filter_by(worker_id=worker.id).all()

    request_order = {'Accepted': 0, 'Pending': 1, 'Rejected': 2, 'Closed': 3}
    requested_jobs = sorted(requests, key=lambda request: request_order.get(request.status, 4))
    
    return render_template("workers/worker_homepage.html",worker = worker, jobs=sorted_jobs, requests=requested_jobs)


# ------------- Handling Jobs by  Worker ----------------
@app.route('/new_job')
@auth_required
def new_job():
    return render_template("jobs/new_job.html")

@app.route('/new_job', methods = ["POST"])
@auth_required
def new_job_post():
    name = request.form.get("name")
    bp = request.form.get("bp")
    worker_id = session["user_id"]

    if not name or not bp:
        flash("Please provide both name and base price")
        return redirect(url_for('new_job'))

        
    job = Job(name=name, bp=bp, worker_id=worker_id)
    db.session.add(job)
    db.session.commit() 

    flash("New job created successfully!")
    return redirect(url_for('worker_homepage'))   
    

@app.route('/edit_job/<int:job_id>', methods=['GET', 'POST'])
@auth_required
def edit_job(job_id):
    job = Job.query.get(job_id)
    if request.method == 'POST':
        name = request.form.get('name')
        bp = request.form.get('bp')

        job.name = name
        job.bp = bp

        db.session.commit()

        return redirect(url_for('worker_homepage'))

    return render_template('jobs/edit_job.html', job=job)








# ------------------Handling Requests in Worker Page----------------

@app.route('/view_request/<int:request_id>')
@auth_required
def view_request(request_id):
    request = Request.query.get(request_id)
    return render_template('requests/view_requests.html', request=request)

@app.route('/approve_request/<int:request_id>')
@auth_required
def approve_request(request_id):
    request = Request.query.get(request_id)
    request.status = "Approved"
    db.session.commit()
    flash("Request approved successfully!")
    return redirect(url_for('worker_homepage'))


@app.route('/reject_request/<int:request_id>')
@auth_required
def reject_request(request_id):
    request = Request.query.get(request_id)
    request.status = "Rejected"
    db.session.commit()
    flash("Request rejected successfully!")
    return redirect(url_for('worker_homepage'))



# Delete Job
@app.route('/worker/job/<int:job_id>/delete', methods=['POST'])
@auth_required 
def worker_delete_job_post(job_id):
    job = Job.query.get(job_id)
    if job:
        db.session.delete(job)
        db.session.commit()
        flash("Job deleted successfully.", "success")
    else:
        flash("Job not found.", "danger")
    return redirect(url_for('worker_homepage'))  





# ------------------------------------------------------End of Worker Routes ---------------------------------------------------



# --------------------------------------------------------user routes-------------------------------------------------
@app.route('/user_homepage')
@auth_required
def user_homepage():
    id = session["user_id"]
    user = User.query.get(id)
    services = Services.query.all()
    requests = Request.query.filter_by(user_id=id).all()

    status_order = {'Approved': 0, 'Pending': 1, 'Closed': 2, 'Rejected': 3}

    sorted_requests = sorted(requests, key=lambda request: status_order.get(request.status, 4))

    return render_template("user/user_homepage.html", user=user, services=services, requests=sorted_requests)

# Search Bar Route
@app.route('/search_services')
@auth_required
def search_services():
    id = session.get("user_id")
    user = User.query.get(id)
    
    query = request.args.get('query', '')
    filter_criteria = request.args.get('filter_criteria', 'service')  # Default to 'service'
    
    services = []
    workers = []
    jobs = []

    if query:
        if filter_criteria == 'service':
            services = Services.query.outerjoin(Job, Services.id == Job.worker_id) \
                .filter(
                    (Services.name.ilike(f'%{query}%')) |
                    (Job.name.ilike(f'%{query}%'))
                ).all()
            if not services:
                flash("Service Not Found.")
                return redirect(url_for("user_homepage"))
        
        # Filter by worker name
        elif filter_criteria == 'worker':
            workers = Worker.query.filter(Worker.name.ilike(f'%{query}%')).all()
            if not workers:
                flash("Worker Not Found.")
                return redirect(url_for("user_homepage"))
        
        # Filter by price
        elif filter_criteria == 'price':
            try:
                price_query = float(query)
                jobs = Job.query.filter(Job.bp <= price_query, Job.approved == "True").all()
            except ValueError:
                jobs = []  
            if not jobs:
                flash("Please put correct price.")
                return redirect(url_for("user_homepage"))
    
    else:
        flash("Put something to search")
        return redirect(url_for("user_homepage"))
    
    return render_template(
        "user/search_results.html", 
        user=user, 
        services=services, 
        workers=workers, 
        jobs=jobs,
        query = query
    )




# User Service Bookings Handling
@app.route('/user_bookings/<int:user_id>')
@auth_required
def user_bookings(user_id):
    services = Services.query.all()
    requests = Request.query.filter_by(user_id=user_id).all()  # Fixed to use user_id
    status_order = {'Approved': 0, 'Pending': 1, 'Closed': 2, 'Rejected': 3}

    sorted_requests = sorted(requests, key=lambda request: status_order.get(request.status, 4))
    user = User.query.get(user_id)
    
    return render_template("user/my_bookings.html", user=user, services=services, requests=sorted_requests)

@app.route("/user_services/<int:service_id>")
@auth_required
def user_services(service_id):
    service = Services.query.get(service_id)
    return render_template("user/services.html", service = service)




# Request Routes
@app.route('/service_request/<int:job_id>')
@auth_required
def service_request(job_id):

    job = Job.query.get(job_id)
    return render_template('requests/new_request.html', job=job)


@app.route('/service_request/<int:job_id>', methods=['POST'])
@auth_required
def service_request_post(job_id):
    
    user_id = session.get('user_id')

    job = Job.query.get(job_id)
    worker_id = job.worker.id

    existing_request = Request.query.filter_by(job_id=job_id, user_id=user_id).first()

    if existing_request and (existing_request.status != "Closed" and existing_request.status != "Rejected"):
        flash("Service already booked!", "warning")
        return redirect(url_for("service_request", job_id=job_id))

    worker = Worker.query.get(worker_id)

    date_of_job_str = request.form.get('date_of_job')
    if not date_of_job_str:
        flash("Please select a valid job date.", "danger")
        return redirect(url_for("service_request", job_id=job_id))

    try:
        date_of_job = datetime.strptime(date_of_job_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format. Please select a valid date.", "danger")
        return redirect(url_for("service_request", job_id=job_id))

    special_instructions = request.form.get('special_instructions', '')

    new_request = Request(
        user_id=user_id,  
        job_id=job_id,
        service_id=worker.service_id,
        worker_id=worker_id,
        date_of_job=date_of_job,
        special_instructions=special_instructions
    )

    db.session.add(new_request)
    db.session.commit()

    flash('Service request has been successfully sent!', 'success')
    return redirect(url_for('user_homepage'))



@app.route('/revoke_request/<int:request_id>', methods=['POST'])
@auth_required
def revoke_request(request_id):
    request = Request.query.get(request_id)

    if request.status == 'Pending':
        db.session.delete(request)
        db.session.commit()
        flash('The request has been successfully revoked.', 'success')
    else:
        flash('Only pending requests can be revoked.', 'warning')

    return redirect(url_for('user_homepage'))


@app.route('/complete_request/<int:request_id>', methods=['GET', 'POST'])
@auth_required
def complete_request(request_id):
    service_request = Request.query.get(request_id)  

    if flask_request.method == 'POST':
        if service_request.status == 'Approved':
            job = Job.query.get(service_request.job_id)
            worker = Worker.query.get(service_request.worker_id)

            # Extract ratings from the form
            job_rating = float(request.form['rating'])
            worker_rating = float(request.form['worker_rating'])

            # Update the ratings for both job and worker
            job.update_rating(job_rating)
            worker.update_rating(worker_rating)

            # Mark the request as completed
            service_request.status = 'Closed'
            db.session.commit()

            flash('The request has been marked as complete.', 'success')
        else:
            flash('Only approved requests can be marked as complete.', 'warning')

        return redirect(url_for('user_homepage'))

    if flask_request.method == 'GET':  
        return render_template("requests/complete_request.html", request=service_request, job=service_request.job, worker=service_request.worker)

