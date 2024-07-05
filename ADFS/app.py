from flask import Flask, request, redirect, url_for, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

SAML_PATH = '/var/www/html/adfs/saml'

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    return auth

def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'script_name': request.path,
        'server_port': request.host.split(':')[1] if ':' in request.host else '443' if request.scheme == 'https' else '80',
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/')
def index():
    if 'samlUserdata' in session:
        return '''
            <h1>Home Page VS ADFS Aufgaben</h1>
            <p>Welcome, user!</p>
            <a href="/secure">Secure Page</a><br>
            <a href="/logout">Logout</a>
        '''
    else:
        return '''
            <h1>Home Page VS ADFS Aufgaben</h1>
            <a href="/login">Login</a>
        '''


@app.route('/login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs/', methods=['POST'])
def acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        if 'AuthNRequestID' in session:
            del session['AuthNRequestID']
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlSessionIndex'] = auth.get_session_index()
        return redirect(url_for('secure'))
    else:
        return 'Error when processing SAML Response: %s' % ', '.join(errors)

@app.route('/secure')
def secure():
    if 'samlUserdata' in session:
        attributes = session['samlUserdata']
        return f'Secure Page<br><pre>{attributes}</pre>'
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session['samlNameId'] if 'samlNameId' in session else None
    session_index = session['samlSessionIndex'] if 'samlSessionIndex' in session else None
    return redirect(auth.logout(name_id=name_id, session_index=session_index))

if __name__ == '__main__':
    app.run()
