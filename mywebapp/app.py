from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, current_user, UserMixin


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db = SQLAlchemy()
db.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean(), nullable=False, default=True)
    tasks = db.relationship('Task', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)
    
    def is_authenticated(self):
        return True

    def is_user_active(self):
        return self.is_active

    def is_anonymous(self):
        return False


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default="Pending") 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def __repr__(self):
        return f"Task('{self.title}', '{self.description}', '{self.completed}', '{self.status}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('base.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route("/register", methods=("POST", "GET"))
def register():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Құпия сөздер бірдей емес', 'danger')
            return render_template('register.html')
        try:
            hash = generate_password_hash(password)
            u = User(username=email, password=hash)
            db.session.add(u)
            db.session.flush()
            db.session.commit()
        except:
            db.session.rollback()
            print("Ошибка добавления в БД")

        flash('Тіркеу сәтті өтті', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Сіз жүйеге сәтті кірдіңіз', 'success')
            return redirect(url_for('home'))
        else:
            flash('Пайдаланушы аты немесе құпия сөз қате', 'danger')

    return render_template('login.html')


@app.route('/home')
@login_required
def home():
    return render_template('base.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Сіз жүйеден сәтті шықтыңыз', 'success')
    return redirect(url_for('login'))


@app.route('/tasks')
@login_required
def tasks():
    user_tasks = Task.query.filter_by(user_id=current_user.id, completed=False).all()
    all_tasks = Task.query.filter_by(completed=False).all()
    return render_template('tasks.html', user_tasks=user_tasks, all_tasks=all_tasks)


@app.route('/task/add', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        if not title or not description: 
            flash('Қате: Барлық өрістерді толтыру қажет!', 'danger')
        else:
            task = Task(title=title, description=description, user_id=current_user.id)
            db.session.add(task)
            db.session.commit()
            flash('Тапсырма сәтті қосылды!', 'success')
            return redirect(url_for('tasks'))
    return render_template('add_task.html')



@app.route('/task/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_task(id):
    task = Task.query.get_or_404(id)
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        db.session.commit()
        flash('Сәтті жаңартылды!', 'success')
        return redirect(url_for('tasks'))
    return render_template('edit_task.html', task=task)


@app.route('/tasks/delete/<int:id>', methods=['POST'])
@login_required
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    flash('Тапсырма жойылды!', 'success')
    return redirect(url_for('tasks'))


@app.route('/assign_task', methods=['GET', 'POST'])
@login_required
def assign_task():
    if request.method == 'POST':
        
        task_id = request.form.get('task')
        email = request.form.get('email')

        
        if not task_id or not email:
            flash('Заполните все поля', 'danger')
        else:
           
            task = Task.query.get_or_404(task_id)

          
            user = User.query.filter_by(username=email).first_or_404()

            
            task.user = user

        
            db.session.commit()
            flash('Тапсырма пайдаланушыға сәтті тағайындалды', 'success')
            return redirect(url_for('tasks'))
    else:
        tasks = Task.query.all()
        users = User.query.all()
        return render_template('assign_task.html', tasks=tasks, users=users)


@app.route('/assigned_tasks')
@login_required
def assigned_tasks():
    user_tasks = Task.query.filter(Task.user != current_user, Task.user != None).all()
    return render_template('assigned_tasks.html', user_tasks=user_tasks)


@app.route('/complete_task/<int:id>', methods=['POST'])
@login_required
def complete_task(id):
    task = Task.query.get_or_404(id)
    task.completed = True
    task.status = "Completed" 
    db.session.commit()
    flash('Тапсырма орындалды!', 'success')
    return redirect(url_for('tasks'))


if __name__ == '__main__':
    app.run(debug=True)