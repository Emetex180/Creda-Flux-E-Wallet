from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import random
import string
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'standard-chartered-bank-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# FIXED: Session configuration
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# FIXED: CORS Configuration - ADDED YOUR DOMAINS
CORS(app,
     supports_credentials=True,
     origins=[
         'https://credaflux.netlify.app',
         'https://credaflux.online',
         'https://www.credaflux.online',
         'https://scbanking.pythonanywhere.com',
         'https://SCBanking.pythonanywhere.com',
         'http://localhost:3000',
         'http://127.0.0.1:3000',
         'http://localhost:8000',
         'http://127.0.0.1:8000',
         'http://localhost:5000'
     ])

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(30), unique=True, nullable=False)
    bank_name = db.Column(db.String(100), nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    pin = db.Column(db.String(4), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(20), unique=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    status = db.Column(db.String(20), default='Processing')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_transactions')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_transactions')

# Exchange rates
EXCHANGE_RATES = {
    'HUF_TO_USD': 0.0028,
    'USD_TO_HUF': 357.14
}

# NEW: Helper function to format money with commas
def format_money(amount):
    """Format money with commas for thousands, millions, etc."""
    return f"{amount:,.2f}"

# Helper functions
def generate_account_number(currency):
    if currency == 'HUF':
        country_code = 'HU'
        check_digits = ''.join(random.choices(string.digits, k=2))
        bank_code = ''.join(random.choices(string.digits, k=3))
        branch_code = ''.join(random.choices(string.digits, k=4))
        account_number = ''.join(random.choices(string.digits, k=16))
        return f"{country_code}{check_digits} {bank_code} {branch_code} {account_number}"
    else:
        return ''.join(random.choices(string.digits, k=10))

def generate_transaction_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

# Initialize database
def initialize_database():
    with app.app_context():
        db.create_all()

        # Create admin user
        if not User.query.filter_by(is_admin=True).first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                name='System Administrator',
                account_number='ADMIN001',
                bank_name='Standard Chartered',
                currency='USD',
                pin='0000',
                is_admin=True,
                balance=0.0
            )
            db.session.add(admin)

            # Sample users
            sample_users = [
                # HUF accounts
                {'name': 'Balázs Kovács', 'account_number': 'HU72 1177 3016 0000 1234 5678 0000', 'bank_name': 'OTP Bank', 'currency': 'HUF'},
                {'name': 'Anna Szabó', 'account_number': 'HU12 1110 0000 0000 9876 5432 0000', 'bank_name': 'K&H Bank', 'currency': 'HUF'},
                {'name': 'Gábor Tóth', 'account_number': 'HU89 1160 0000 0000 4567 8901 0000', 'bank_name': 'Erste Bank Hungary', 'currency': 'HUF'},
                {'name': 'Eszter Nagy', 'account_number': 'HU45 1040 0000 0000 3210 9876 0000', 'bank_name': 'CIB Bank', 'currency': 'HUF'},
                {'name': 'László Horváth', 'account_number': 'HU63 1201 0000 0000 6543 2109 0000', 'bank_name': 'Raiffeisen Bank', 'currency': 'HUF'},

                # USD accounts
                {'name': 'Michael Johnson', 'account_number': '0310024587', 'bank_name': 'Bank of America', 'currency': 'USD'},
                {'name': 'Emily Davis', 'account_number': '0829015372', 'bank_name': 'Wells Fargo', 'currency': 'USD'},
                {'name': 'Christopher Miller', 'account_number': '1250048793', 'bank_name': 'Chase Bank', 'currency': 'USD'},
                {'name': 'Sarah Thompson', 'account_number': '2110839021', 'bank_name': 'Citibank', 'currency': 'USD'},
                {'name': 'David Anderson', 'account_number': '0631074589', 'bank_name': 'PNC Bank', 'currency': 'USD'},
            ]

            for user_data in sample_users:
                username = user_data['name'].lower().replace(' ', '_').replace('á', 'a').replace('é', 'e').replace('í', 'i').replace('ó', 'o').replace('ú', 'u').replace('ő', 'o').replace('ű', 'u')
                user = User(
                    username=username,
                    password=generate_password_hash('password123'),
                    name=user_data['name'],
                    account_number=user_data['account_number'],
                    bank_name=user_data['bank_name'],
                    currency=user_data['currency'],
                    pin='1234',
                    is_admin=False,
                    balance=10000.0
                )
                db.session.add(user)

            db.session.commit()
            print("Database initialized successfully!")

# Add session debugging middleware
@app.before_request
def log_session_info():
    print(f"Session data: {dict(session)}")
    print(f"Request origin: {request.headers.get('Origin')}")
    print(f"Cookies: {request.cookies}")

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin in [
        'https://credaflux.netlify.app',
        'https://credaflux.online',
        'https://www.credaflux.online',
        'https://scbanking.pythonanywhere.com',
        'https://SCBanking.pythonanywhere.com',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:8000',
        'http://127.0.0.1:8000',
        'http://localhost:5000'
    ]:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# ===== API ROUTES =====

@app.route('/')
def home():
    return jsonify({
        'message': 'TradeWavee E-wallet API is running!',
        'status': 'active',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api')
def api_home():
    return jsonify({
        'message': 'TradeWavee E-wallet API is running!',
        'status': 'active',
        'version': '1.0',
        'endpoints': {
            'login': '/api/login',
            'user_dashboard': '/api/user/dashboard',
            'admin_users': '/api/admin/users',
            'check_auth': '/api/check_auth',
            'search_accounts': '/api/search_accounts',
            'make_transaction': '/api/make_transaction',
            'logout': '/api/logout',
            'test': '/api/test'
        },
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/test', methods=['GET'])
def test_connection():
    return jsonify({
        'success': True,
        'message': 'Backend is working!',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin

        # Force session to be saved
        session.modified = True

        print(f"User logged in: {user.username}, is_admin: {user.is_admin}")
        print(f"Session after login: {dict(session)}")

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'username': user.username,
                'is_admin': user.is_admin,
                'account_number': user.account_number,
                'bank_name': user.bank_name,
                'currency': user.currency,
                'balance': user.balance,
                'formatted_balance': format_money(user.balance)  # ADDED FORMATTED BALANCE
            }
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'})

@app.route('/api/admin/users')
def get_admin_users():
    print(f"Admin users check - Session: {dict(session)}")

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})

    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized - Admin access required'})

    users = User.query.filter_by(is_admin=False).all()
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'account_number': user.account_number,
            'bank_name': user.bank_name,
            'currency': user.currency,
            'balance': user.balance,
            'formatted_balance': format_money(user.balance)  # ADDED FORMATTED BALANCE
        })

    return jsonify({'success': True, 'users': users_data})

@app.route('/api/admin/users', methods=['POST'])
def create_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized'})

    try:
        data = request.get_json()
        name = data['name']
        username = data['username']
        password = data['password']
        currency = data['currency']
        bank_name = data['bank_name']
        pin = data['pin']

        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'})

        account_number = generate_account_number(currency)

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            name=name,
            account_number=account_number,
            bank_name=bank_name,
            currency=currency,
            pin=pin,
            is_admin=False,
            balance=0.0
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'success': True, 'message': 'User created successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# FIXED DELETE FUNCTION - HANDLES TRANSACTIONS AND ERRORS
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    print(f"🔴 DELETE request for user ID: {user_id}")
    print(f"Session: {dict(session)}")

    try:
        # Check authentication
        if 'user_id' not in session:
            print("❌ No user_id in session")
            return jsonify({'success': False, 'message': 'Not authenticated'})

        if not session.get('is_admin'):
            print("❌ User is not admin")
            return jsonify({'success': False, 'message': 'Not authorized - Admin access required'})

        user = User.query.get(user_id)
        print(f"🔍 User found: {user}")

        # Check if user exists
        if not user:
            print("❌ User not found")
            return jsonify({'success': False, 'message': 'User not found'})

        # Check if user is admin (prevent deleting admins)
        if user.is_admin:
            print("❌ Cannot delete admin user")
            return jsonify({'success': False, 'message': 'Cannot delete admin users'})

        print(f"🗑️ Deleting related transactions for user {user_id}...")
        # Delete related transactions first to avoid foreign key constraints
        transactions_to_delete = Transaction.query.filter(
            (Transaction.sender_id == user_id) | (Transaction.receiver_id == user_id)
        ).all()

        print(f"📊 Found {len(transactions_to_delete)} transactions to delete")

        for transaction in transactions_to_delete:
            db.session.delete(transaction)
            print(f"🗑️ Deleted transaction: {transaction.transaction_id}")

        # Delete the user
        print(f"🗑️ Deleting user: {user.name} (ID: {user.id})")
        db.session.delete(user)
        db.session.commit()

        print("✅ User deleted successfully")
        return jsonify({'success': True, 'message': 'User deleted successfully'})

    except Exception as e:
        print(f"💥 Error deleting user: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error deleting user: {str(e)}'}), 500

@app.route('/api/user/dashboard')
def user_dashboard():
    print(f"User dashboard check - Session: {dict(session)}")

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})

    if session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Admins cannot access user dashboard'})

    user = User.query.get(session['user_id'])
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user.id) | (Transaction.receiver_id == user.id)
    ).order_by(Transaction.created_at.desc()).limit(10).all()

    transactions_data = []
    for transaction in transactions:
        transactions_data.append({
            'id': transaction.id,
            'transaction_id': transaction.transaction_id,
            'sender_name': transaction.sender.name,
            'receiver_name': transaction.receiver.name,
            'amount': transaction.amount,
            'currency': transaction.currency,
            'formatted_amount': format_money(transaction.amount),  # ADDED FORMATTED AMOUNT
            'status': transaction.status,
            'created_at': transaction.created_at.isoformat()
        })

    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'account_number': user.account_number,
            'bank_name': user.bank_name,
            'currency': user.currency,
            'balance': user.balance,
            'formatted_balance': format_money(user.balance),  # ADDED FORMATTED BALANCE
            'pin': user.pin
        },
        'transactions': transactions_data
    })

@app.route('/api/search_accounts')
def search_accounts():
    query = request.args.get('q', '')

    if not query or len(query) < 2:
        return jsonify([])

    users = User.query.filter(
        (User.account_number.contains(query)) | (User.name.contains(query))
    ).filter_by(is_admin=False).all()

    results = []
    for user in users:
        results.append({
            'id': user.id,
            'name': user.name,
            'account_number': user.account_number,
            'bank_name': user.bank_name,
            'currency': user.currency,
            'balance': user.balance,
            'formatted_balance': format_money(user.balance)  # ADDED FORMATTED BALANCE
        })

    return jsonify(results)

@app.route('/api/make_transaction', methods=['POST'])
def make_transaction():
    if 'user_id' not in session or session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized'})

    try:
        data = request.get_json()
        sender = User.query.get(session['user_id'])
        receiver_id = data['receiver_id']
        amount = float(data['amount'])
        pin = data['pin']

        if sender.pin != pin:
            return jsonify({'success': False, 'message': 'Invalid PIN'})

        if sender.balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'})

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid amount'})

        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'success': False, 'message': 'Recipient account not found'})

        # Create transaction
        transaction = Transaction(
            transaction_id=generate_transaction_id(),
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=amount,
            currency=sender.currency,
            status='Processing'
        )

        db.session.add(transaction)

        # Update balances
        if sender.currency == receiver.currency:
            sender.balance -= amount
            receiver.balance += amount
        else:
            if sender.currency == 'HUF' and receiver.currency == 'USD':
                converted_amount = amount * EXCHANGE_RATES['HUF_TO_USD']
                sender.balance -= amount
                receiver.balance += converted_amount
            else:
                converted_amount = amount * EXCHANGE_RATES['USD_TO_HUF']
                sender.balance -= amount
                receiver.balance += converted_amount

        transaction.status = 'Completed'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Transaction completed successfully',
            'transaction_id': transaction.transaction_id,
            'formatted_amount': format_money(amount)  # ADDED FORMATTED AMOUNT
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/transaction_receipt/<transaction_id>')
def transaction_receipt(transaction_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authorized'})

    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first()
    if not transaction:
        return jsonify({'success': False, 'message': 'Transaction not found'})

    user = User.query.get(session['user_id'])
    if user.id != transaction.sender_id and user.id != transaction.receiver_id and not user.is_admin:
        return jsonify({'success': False, 'message': 'Not authorized'})

    receipt_data = {
        'transaction_id': transaction.transaction_id,
        'sender_name': transaction.sender.name,
        'sender_account': transaction.sender.account_number,
        'receiver_name': transaction.receiver.name,
        'receiver_account': transaction.receiver.account_number,
        'amount': transaction.amount,
        'formatted_amount': format_money(transaction.amount),  # ADDED FORMATTED AMOUNT
        'currency': transaction.currency,
        'status': transaction.status,
        'created_at': transaction.created_at.isoformat()
    }

    return jsonify({'success': True, 'receipt': receipt_data})

# ===== ADMIN FUND MANAGEMENT ROUTES =====

@app.route('/api/admin/deposit', methods=['POST'])
def admin_deposit():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized - Admin access required'})

    try:
        data = request.get_json()
        user_id = data.get('user_id')
        amount = float(data.get('amount'))
        description = data.get('description', 'Admin Deposit')

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})

        # Create deposit transaction (admin as sender, user as receiver)
        transaction = Transaction(
            transaction_id=generate_transaction_id(),
            sender_id=session['user_id'],  # Admin's ID
            receiver_id=user_id,
            amount=amount,
            currency=user.currency,
            status='Completed',
            created_at=datetime.utcnow()
        )

        # Update user balance
        user.balance += amount

        db.session.add(transaction)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully deposited {format_money(amount)} {user.currency} to {user.name}',  # FORMATTED
            'new_balance': user.balance,
            'formatted_new_balance': format_money(user.balance),  # ADDED FORMATTED BALANCE
            'transaction_id': transaction.transaction_id
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/admin/withdraw', methods=['POST'])
def admin_withdraw():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized - Admin access required'})

    try:
        data = request.get_json()
        user_id = data.get('user_id')
        amount = float(data.get('amount'))
        description = data.get('description', 'Admin Withdrawal')

        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})

        if user.balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'})

        # Create withdrawal transaction (user as sender, admin as receiver)
        transaction = Transaction(
            transaction_id=generate_transaction_id(),
            sender_id=user_id,
            receiver_id=session['user_id'],  # Admin's ID
            amount=amount,
            currency=user.currency,
            status='Completed',
            created_at=datetime.utcnow()
        )

        # Update user balance
        user.balance -= amount

        db.session.add(transaction)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully withdrew {format_money(amount)} {user.currency} from {user.name}',  # FORMATTED
            'new_balance': user.balance,
            'formatted_new_balance': format_money(user.balance),  # ADDED FORMATTED BALANCE
            'transaction_id': transaction.transaction_id
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/admin/transactions')
def get_admin_transactions():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Not authorized - Admin access required'})

    try:
        # Get all transactions involving admin (either as sender or receiver)
        transactions = Transaction.query.filter(
            (Transaction.sender_id == session['user_id']) |
            (Transaction.receiver_id == session['user_id'])
        ).order_by(Transaction.created_at.desc()).limit(50).all()

        transactions_data = []
        for transaction in transactions:
            transaction_type = 'Deposit' if transaction.receiver_id != session['user_id'] else 'Withdrawal'
            target_user = transaction.receiver if transaction_type == 'Deposit' else transaction.sender

            transactions_data.append({
                'id': transaction.id,
                'transaction_id': transaction.transaction_id,
                'type': transaction_type,
                'target_user': target_user.name,
                'target_account': target_user.account_number,
                'amount': transaction.amount,
                'formatted_amount': format_money(transaction.amount),  # ADDED FORMATTED AMOUNT
                'currency': transaction.currency,
                'status': transaction.status,
                'created_at': transaction.created_at.isoformat()
            })

        return jsonify({'success': True, 'transactions': transactions_data})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/logout')
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/check_auth')
def check_auth():
    print(f"Auth check - Session: {dict(session)}")

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'username': user.username,
                'is_admin': user.is_admin,
                'balance': user.balance,
                'formatted_balance': format_money(user.balance)  # ADDED FORMATTED BALANCE
            }
        })
    return jsonify({'success': False, 'message': 'Not authenticated'})

@app.route('/api/debug/session')
def debug_session():
    return jsonify({
        'session_data': dict(session),
        'cookies_received': dict(request.cookies),
        'origin': request.headers.get('Origin'),
        'user_agent': request.headers.get('User-Agent')
    })

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True, host='0.0.0.0', port=5000)