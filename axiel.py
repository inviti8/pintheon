import os
from flask import Flask, jsonify, request
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query

app = Flask(__name__)
app.secret_key = os.urandom(24)

db = TinyDB('db.json')
log_book = db.table('log_book')

@app.route('/')
def home():
 return jsonify(message='||AXIEL||')

@app.route('/data', methods=['POST'])
def create_data():
 data = request.get_json()
 # Here you would normally save the data to a database
 return jsonify(message='Data received', data=data), 201

if __name__ == '__main__':
 app.run(host='0.0.0.0', debug=True)