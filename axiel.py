import os
from flask import Flask, render_template, request, session, redirect, jsonify, url_for
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query

app = Flask(__name__)
app.secret_key = os.urandom(24)

db = TinyDB('db.json')
log_book = db.table('log_book')

SCRIPT_DIR = os.path.abspath( os.path.dirname( __file__ ) )
STATIC_PATH = os.path.join(SCRIPT_DIR, "static")
COMPONENT_PATH = os.path.join(SCRIPT_DIR, "components")

def _load_components(comp):
 result = None
 with open(os.path.join(COMPONENT_PATH, f'{comp}.html'), 'r') as f:
        result = f.read()

 return result

def _load_js(comp):
 return url_for('static', filename=f'{comp}.js')
 

@app.route('/')
def home():
 components=_load_components('new_node')
 js=_load_js('new_node')
 shared_dialogs=_load_components('shared_dialogs')
 shared_dialogs_js=_load_js('shared_dialogs')
 return render_template('index.html', components=components, js=js, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js)
 #return jsonify(message='||AXIEL||')


@app.route('/data', methods=['POST'])
def create_data():
 data = request.get_json()
 # Here you would normally save the data to a database
 return jsonify(message='Data received', data=data), 201

if __name__ == '__main__':
 app.run(host='0.0.0.0', debug=True)