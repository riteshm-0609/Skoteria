import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

#DATABASE PART
mysql = MySQL()
app.secret_key = 'rootpasswordgiven'
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'rootpasswordgiven'
app.config['MYSQL_DATABASE_DB'] = 'test'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)
#MONGOPART
app.config["MONGO_URI"] = "mongodb://localhost:27017/test"
mongo = PyMongo(app)
conn = mysql.connect()
cursor =conn.cursor()
class block:
	def __init__(self,current_transactions):
        self.current_transactions = current_transactions
		self.last_block = #retrive from database
	    self.proof = block.proof_of_work(last_block)


	def hash(block):
	    """
	    Creates a SHA-256 hash of a Block

	    :param block: Block
	    """

	    # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
	    block_string = json.dumps(block, sort_keys=True).encode()
	    return hashlib.sha256(block_string).hexdigest()

	def proof_of_work(self, last_block):
	    """
	    Simple Proof of Work Algorithm:

	     - Find a number p' such that hash(pp') contains leading 4 zeroes
	     - Where p is the previous proof, and p' is the new proof
	     
	    :param last_block: <dict> last Block
	    :return: <int> last_block = blockchain.last_block
	    proof = blockchain.proof_of_work(last_block)

	    """

	    last_proof = last_block['proof']
	    last_hash = self.hash(last_block)

	    proof = 0
	    while self.valid_proof(last_proof, proof, last_hash) is False:
	        proof += 1

	    return proof

	def valid_proof(last_proof, proof, last_hash):
	    """
	    Validates the Proof

	    :param last_proof: <int> Previous Proof
	    :param proof: <int> Current Proof
	    :param last_hash: <str> The hash of the Previous Block
	    :return: <bool> True if correct, False if not.

	    """

	    guess = f'{last_proof}{proof}{last_hash}'.encode()
	    guess_hash = hashlib.sha256(guess).hexdigest()
	    return guess_hash[:4] == "0000"


@app.route('/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    error = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM employee WHERE username = %s AND password = %s', (username, password))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[2]
            # Redirect to home page
            return render_template('start.html')
        else:
            # Account doesnt exist or username/password incorrect
            error = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('login.html', error=error)

@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
	if request.form=='POST':
		sender=
	current_transactions.append({
        'sender': sender,
        'recipient': recipient,
        'amount': amount,
    })



if __name__ == '__main__':
	app.run(debug=True)	