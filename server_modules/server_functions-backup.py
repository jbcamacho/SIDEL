import OpenSSL
import re
from os import path, listdir, getcwd
from datetime import datetime
from subprocess import check_output
from hashlib import md5

def look_for_cert_by_serial(cert_serial):
    ### LOOK FOR CERT BY SERIAL IN THE CA FOLDER (easyrsa) ###
    curr_path = getcwd() + "/credentials"
    #list_certs = list_files_by_extension(curr_path, ".crt")
    for cert_name in listdir(curr_path):
        if cert_name.endswith(".crt"):
            with open(curr_path + "/" + cert_name, "rb") as f:
                st_cert = f.read()
            client_cert = OpenSSL.crypto.load_certificate(type = OpenSSL.crypto.FILETYPE_PEM, buffer = st_cert)
            if str(client_cert.get_serial_number()).encode() == cert_serial:
                return client_cert
    return b""
#look_for_cert_by_serial

def open_cert(cert_name):
    ### PUBLIC KEY FROM .CERT ###
    print(getcwd())
    path_to_cert = getcwd() + "/temp/" + cert_name #+ ".crt"
    with open(path_to_cert, "rb") as f:
        st_cert = f.read()
    client_cert = OpenSSL.crypto.load_certificate(type = OpenSSL.crypto.FILETYPE_PEM, buffer = st_cert)
    #cert_subject = client_cert.get_subject()
    #client_name = cert_subject.CN
    client_cert_serial = str(client_cert.get_serial_number()).encode()
    
    return client_cert, client_cert_serial
#open_cert

def verify_cert(cert):
    if cert.has_expired():
        return 0 #print("The cert has expired.")
    return 1
#verify_cert

def open_privKey(privKey_name):
    ### PRIVATE KEY FROM .KEY ###
    path_to_privKey = getcwd() + "/temp/" + privKey_name #+ ".key"
    with open(path_to_privKey, "rb") as f:
        st_priv_key = f.read()
    client_priv_key = OpenSSL.crypto.load_privatekey(type = OpenSSL.crypto.FILETYPE_PEM, buffer = st_priv_key)
    
    return client_priv_key
#open_privKey

def sign_doc(privKey, document_name):
    ### READ DATA TO SIGN ###
    # path_to_document = "/temp/" + document_name #+ ".key"
    path_to_document = path.join('temp', document_name)
    with open(path_to_document, "rb") as f:
        #file_name = f.name.split("." + f.name.split(".")[-1])[0]
        data_to_sign = f.read()
    doc_sign = OpenSSL.crypto.sign(pkey = privKey, data = data_to_sign, digest = "sha512")
    
    return doc_sign
#sign_doc

def save_signature(document_name, doc_sign, client_cert_serial, prev_signature_name = b""):
    ### SAVE SIGNATURE ###
    now = datetime.now() # current date and time
    timestamp = now.strftime("%m%d%Y%H%M%S")
    #print("date and time:", timestamp)
    file_name_signature = getcwd() + "/signs/" + document_name.split(".")[0] + "_" + timestamp + ".sig"
    prev_data = b""

    ### if signed by multiple users needs to get the data from the previous sign ###
    if prev_signature_name != b"":
        path_to_prev_signature_file = getcwd() + "/temp/" + prev_signature_name #+ .sig
        if path.exists(path_to_prev_signature_file):
            with open(path_to_prev_signature_file, "rb") as f:
                prev_data = f.read()
    ### if signed by multiple users needs to get the data from the previous sign ###

    with open(file_name_signature, "wb") as s:
        if prev_data != b"":
            s.write(prev_data)
        s.write(b"serial:")
        s.write(client_cert_serial)
        s.write(b"signature:")
        s.write(doc_sign)

    return file_name_signature


def get_signs_in_signatureFile(file_name_signature):
    path_to_signature = getcwd() + "/temp/" + file_name_signature #+ .sig
    with open(path_to_signature, "rb") as f:
        s = f.read()
    signatures = re.split(b"(serial:|signature:)", s)

    return signatures
#sign_doc_multiple

def verify_signature(file_name_signature, signed_document_name):
    signatures = get_signs_in_signatureFile(file_name_signature)
    count_signs = int(len(signatures)/4)
    path_to_document = path.join('temp', signed_document_name)
    with open(path_to_document, "rb") as f:
        signed_document_data = f.read()
    for i_sign in range(count_signs):
        cert_serial = signatures[i_sign*4 + 2]
        sign = signatures[i_sign*4 + 4]
        cert = look_for_cert_by_serial(cert_serial)

        if cert == b"":
            return "cert_not_found"
            # print("not cert found for the given serial: ", cert_serial)
            # break
        if cert.has_expired():
            return "cert_expired"
            # print("The cert: ", cert_serial, " has expired.")
            # break

        try:
            OpenSSL.crypto.verify(cert = cert, signature = sign, data = signed_document_data, digest = "sha512")
            # print("The signature is valid.")
            # return True
        except:
            return "invalid_signature"
            # print("The signature is not valid.")
            # break
    return "valid_signature"
        #i_sign += 4
#verify_signature

def sign_document(cert_name, privKey_name, document_name):
    [client_cert, client_cert_serial]   = open_cert(cert_name)
    cert_status = verify_cert(client_cert)
    if cert_status == 0:
        return "cert_expired"
    client_priv_key                     = open_privKey(privKey_name)
    doc_sign                            = sign_doc(client_priv_key, document_name)
    file_name_signature                 = save_signature(document_name, doc_sign, client_cert_serial)
    #verify_signature(file_name_signature, signed_document)
    return file_name_signature
#main

def sign_document_multipleUsers(cert_name, privKey_name, document_name, prev_signature_name):
    #verify_signature(file_name_signature, signed_document)
    [client_cert, client_cert_serial]   = open_cert(cert_name)
    cert_status = verify_cert(client_cert)
    if cert_status == 0:
        return "cert_expired"
    client_priv_key                     = open_privKey(privKey_name)
    doc_sign                            = sign_doc(client_priv_key, document_name)
    file_name_signature                 = save_signature(document_name, doc_sign, client_cert_serial, prev_signature_name)
    #verify_signature(file_name_signature, signed_document)
    return file_name_signature
#sign_document_multipleUsers

def cert_matches_key(cert_name, privKey_name):
    ### CHECK IF .CERT MATCHES .KEY ###
    # For your SSL certificate: openssl x509 -noout -modulus -in cert.crt | openssl md5
    # For your RSA private key: openssl rsa -noout -modulus -in privkey.txt | openssl md5
    # if both outputs are the same, then it matches!
    path_to_cert = getcwd() + "/temp/" + cert_name
    path_to_privKey = getcwd() + "/temp/" + privKey_name
    cert_metadata = check_output(["openssl", "x509", "-noout", "-modulus", "-in", str(path_to_cert)])
    cert_metadata_digest = md5(cert_metadata).digest()
    key_metadata = check_output(["openssl", "rsa", "-noout", "-modulus", "-in", str(path_to_privKey)])
    key_metadata_digest = md5(key_metadata).digest()
    if cert_metadata_digest == key_metadata_digest:
        return True
    return False
#cert_matches_key

def login_by_credentials(cert_name, privKey_name):
    [client_cert, client_cert_serial]   = open_cert(cert_name)
    cert_status = verify_cert(client_cert)
    if cert_status == 0:
        return "El certificado con el numero de serie " + client_cert_serial + " ha expirado."
    found_cert = look_for_cert_by_serial(client_cert_serial)
    if found_cert == b"":
        return "El certificado proporcionado(" + client_cert_serial + ") no pertenece a SIDEL."
    #client_priv_key                     = open_privKey(privKey_name)
    ### CHECK IF .CERT MATCHES .KEY ###
    if cert_matches_key(cert_name, privKey_name):
        print("LOGIN!")
        return True

    return False
#login_by_credentials

# if __name__ == '__main__':
#     login_by_credentials("Abel-test1.crt", "Abel-test1.key")
