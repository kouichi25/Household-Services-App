from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash
from sqlalchemy import func

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# User model remains unchanged
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(36), unique=True)
    passhash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(36), nullable=False)
    address = db.Column(db.String(70), nullable=False)
    pin = db.Column(db.Integer, nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    requests = db.relationship('Request', backref='user', lazy=True)
    def closed_requests_count(self):
        return sum(1 for request in self.requests if request.status == 'Closed')

# Service model remains unchanged
class Services(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(36), unique=True, nullable=False)
    base_price = db.Column(db.Integer)
    time_required = db.Column(db.Integer)
    description = db.Column(db.String(50))
    workers = db.relationship('Worker', backref='service', lazy=True)
    requests = db.relationship('Request', backref='service', lazy=True)

# Worker model with rating logic
class Worker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(36), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(36), nullable=True)
    age = db.Column(db.Integer, nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    experience = db.Column(db.Integer, nullable=True)
    date_of_join = db.Column(db.Date, default=func.current_date())
    contact = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    address = db.Column(db.String(100), nullable=False)
    pin = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    jobs = db.relationship('Job', backref='worker', lazy=True)
    requests = db.relationship('Request', backref='worker', lazy=True)

    rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)

    def update_rating(self, new_rating):
        if self.rating is None:
            self.rating = 0.0
        if self.rating_count is None:
            self.rating_count = 0

        self.rating_count += 1
        self.rating = ((self.rating * (self.rating_count - 1)) + new_rating) / self.rating_count

    def closed_requests_count(self):
        return sum(1 for request in self.requests if request.status == 'Closed')



class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(36), unique=True, nullable=False)
    bp = db.Column(db.Integer, nullable=True)
    approved = db.Column(db.String(10), default="False")
    worker_id = db.Column(db.Integer, db.ForeignKey('worker.id'), nullable=True)
    requests = db.relationship('Request', backref='job', lazy=True)
    
    # Rating Job
    rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)

    def update_rating(self, new_rating):
        if self.rating is None:
            self.rating = 0.0
        if self.rating_count is None:
            self.rating_count = 0

        self.rating_count += 1
        self.rating = ((self.rating * (self.rating_count - 1)) + new_rating) / self.rating_count





# Request model remains unchanged
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_sent = db.Column(db.Date, default=func.current_date())
    date_of_job = db.Column(db.Date)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    worker_id = db.Column(db.Integer, db.ForeignKey('worker.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default="Pending")
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=True)
    special_instructions = db.Column(db.String(255), nullable=True)

with app.app_context():
    jobs = Job.query.all()
    for job in jobs:
        if job.rating is None:
            job.rating = 0.0
        if job.rating_count is None:
            job.rating_count = 0
        db.session.add(job)

    workers = Worker.query.all()
    for worker in workers:
        if worker.rating is None:
            worker.rating = 0.0
        if worker.rating_count is None:
            worker.rating_count = 0
        db.session.add(worker)
    
    db.session.commit()

# Initialize the database and add an admin user if not exists
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(is_admin=True).first()

    if not admin:
        passhash = generate_password_hash('admin')
        admin = User(username='admin', passhash=passhash, name="admin", address="address", pin=79006, contact="44543", is_admin=True)
        db.session.add(admin)
        db.session.commit()
