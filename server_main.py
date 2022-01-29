#### FLASK LIBS ####
from flask import Flask, render_template, redirect, url_for, request, json
from flask import send_file, send_from_directory, safe_join, abort
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
# from flask import send_file, send_from_directory, safe_join, abort
#### FLASK LIBS ####

#### SYSTEM LIBS ####
from shutil import rmtree
import os, sys
#### SYSTEM LIBS ####

### USER DEFINED MODULES ####
from server_modules import server_functions
from server_modules import sidel_utils as sidel
### USER DEFINED MODULES ####


app = Flask(__name__)

app.config['SECRECT_KEY'] = "71a2c6dabb9caab81d08a2efbd9e40f9519be9c504"
LOGIN_DEBUG = 0
posts = [
    {
        'author'        : 'Juan Bernardo Camacho',
        'title'         : 'SIDEL - Descripción del Diseño del Software',
        'content'       : 'El siguiente documento detalla y especifica el diseño de software para el proyecto “Signado de documentos electrónicos”, abreviado SIDEL para propósitos y futuras referencias en este documento. El documento está basado en el estándar IEEE “Standard for Information Technology —Systems Design— Software Design Descriptions” in IEEE Std 1016-2009, IEEE Computer Society, 2009." [E2]. La estructura del documento puede encontrarse en Annex C (informative) Templates for an SDD.',
        'date_posted'   : 'April 10, 2021',
        #SDD - Link
        'ref'           : 'https://docs.google.com/document/d/1c79yKpaDL3EH27Fg15B6NsseNVodVu_jgjm3S3TCtZs/edit?usp=sharing'
    },
    {
        'author': 'Juan Bernardo Camacho',
        'title': 'SIDEL - Especificación de Requerimientos',
        'content': 'El siguiente documento detalla, específica y establece los requerimientos de software para el proyecto “Signado de documentos electrónicos”, abreviado SIDEL para propósitos y futuras referencias en este documento. El documento está basado en el estándar IEEE Std 830-1998 "IEEE Recommended Practice for Software Requirements Specifications," [E2]. La estructura del documento puede encontrarse en Prototype SRS outline.',
        'date_posted': 'April 10, 2021',
        #SRS - Link
        'ref'           : 'https://docs.google.com/document/d/134TXrmDmqnFcr71c77CzZ18TGKNoCjvxprw-7ntQgu8/edit?usp=sharing'
    }
]

class userCredentials():
    def __init__(self, cert = {}, name=b"", privKey = b"", cert_serial = b"", log = LOGIN_DEBUG):
        self.cert = cert
        self.name = name
        self.privKey = privKey
        self.login = log
        self.cert_serial = cert_serial

DEFAULT_USER = userCredentials()

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts = posts, py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)

@app.route("/register")
def register():
    DEFAULT_USER.login = 0
    return render_template('login.html', py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)

@app.route("/about")
def about():
    return render_template('about.html', title='Sobre SIDEL', py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html', title='Inicio de Sesión', py_login = DEFAULT_USER.login, cert = DEFAULT_USER.cert, userid = DEFAULT_USER.name)

@app.route('/login_auth', methods=['GET'])
def login_auth():
    if request.method == "GET":
        if DEFAULT_USER.login == 0:
            cert_serial_from_js = request.args.get('cert_serial_js')
            cert = server_functions.look_for_cert_by_serial(cert_serial_from_js)
            if cert == b"":
                return "cert_not_found"
            if cert.has_expired():
                return "cert_expired"
            challenge_nonce = sidel.get_nonce()
            return str(challenge_nonce)
        return "Favor de cerrar session."
    return "error"

@app.route('/login_auth_response', methods=['GET'])
def login_auth_response():
    if request.method == "GET":
        if DEFAULT_USER.login == 0:
            cert_serial_from_js = request.args.get('cert_serial_js')
            challenge_from_js = request.args.get('challenge_js')
            challenge_response_from_js = request.args.get('challenge_response_js')
            challenge_verify = server_functions.verify_challenge(challenge_from_js, challenge_response_from_js, cert_serial_from_js)
            if (str(challenge_verify) == "valid_signature"):
                DEFAULT_USER.login = 1
                DEFAULT_USER.cert = request.args.copy()
                DEFAULT_USER.name = DEFAULT_USER.cert['cert_commonName_js']
                del(DEFAULT_USER.cert['challenge_response_js'])
                del(DEFAULT_USER.cert['challenge_js'])
                del(DEFAULT_USER.cert['cert_signature_js'])
            return str(challenge_verify)
        return "invalid_session"
    return "error"


@app.route('/sign_process', methods=['GET'])
def sign_process():
    if request.method == "GET":
        if DEFAULT_USER.login == 1:
            cert_serial = DEFAULT_USER.cert['cert_serial_js']
            signature_from_js = request.args.get('signature_js')
            document_name_from_js = request.args.get('document_name_js')
            sign_response = server_functions. _
            sign_document2(cert_serial, document_name_from_js, signature_from_js)
            if sign_response == "cert_expired":
                return "cert_expired"
            sign_file_name = sign_response.split('/')[-1]
            return sign_file_name
        return "invalid_session"
    return "error"

@app.route('/download_sign_document', methods=['GET'])
def download_sign_document():
    if request.method == "GET":
        file_sign = str(request.args.get('file_sign'))
        return send_from_directory(directory="signs", filename=file_sign, as_attachment=True)
    return "ERROR 404 — Archivo no encontrado, favor de intentar nuevamente."


@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if DEFAULT_USER.login == 1:
        return render_template('sign.html', title="Firma de Documento", py_login = DEFAULT_USER.login, py_sign_success=DEFAULT_USER.login, userid = DEFAULT_USER.name)
    return render_template("error_page.html", error_code = "503", error_name = "Service Unavailable.", error_description = "", py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)


@app.route('/sign_add', methods=['GET', 'POST'])
def sign_add():
    if DEFAULT_USER.login == 1:
        return render_template('sign_add.html', py_login = DEFAULT_USER.login, py_sign_success='', userid = DEFAULT_USER.name)
    return render_template("error_page.html", error_code = "503", error_name = "Service Unavailable.", error_description = "", py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)

@app.route('/sign_add_process', methods=['GET'])
def sign_add_process():
    if request.method == "GET":
        if DEFAULT_USER.login == 1:
            cert_serial = DEFAULT_USER.cert['cert_serial_js']
            signature_from_js = request.args.get('signature_js')
            document_name_from_js = str(request.args.get('document_name_js'))
            prev_sign_name_from_js = str(request.args.get('prev_sign_name_js'))
            sign_response = server_functions.sign_document2(cert_serial, document_name_from_js, signature_from_js, prev_sign_name_from_js)
            if sign_response == "cert_expired":
                return "cert_expired"
            sign_file_name = sign_response.split('/')[-1]
            return sign_file_name
        return "invalid_session"
    return "error"

@app.route('/verify_sign', methods=['GET', 'POST'])
def verify_sign():
    if request.method == 'POST':
        if DEFAULT_USER.login == 1:
            doc_file = request.files['docFile']
            sign_file = request.files['signFile']
            if not os.path.isdir('temp'):
                os.mkdir('temp')
            doc_filepath = os.path.join('temp', doc_file.filename)
            sign_filepath = os.path.join('temp', sign_file.filename)
            doc_file.save(doc_filepath)
            sign_file.save(sign_filepath)
            verify_response = server_functions.verify_signature(sign_file.filename, doc_file.filename)
            return render_template('verify_sign.html', form="verifyForm", verify_response=verify_response, py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)
        return render_template('verify_sign.html', form="verifyForm", py_verify="not_session", py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)
    if DEFAULT_USER.login == 1:
        return render_template('verify_sign.html', form="verifyForm", py_verify="", py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)
    return render_template("error_page.html", error_code = "503", error_name = "Service Unavailable.", error_description = "", py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return error instead of HTML for HTTP errors."""
    return render_template("error_page.html", error_code = e.code, error_name = e.name, error_description = e.description, py_login = DEFAULT_USER.login, userid = DEFAULT_USER.name)

if __name__ == '__main__':
    app.run(debug=True)