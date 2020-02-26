import binascii
import Crypto
import json
import pyqrcode
import smtplib
import requests
import imaplib, email

from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request
from flask import redirect
from flask import send_from_directory
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA512
from collections import OrderedDict
from pyqrcode import QRCode 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, amount):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.amount = amount
    
    def to_dict(self):
        return OrderedDict({
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'amount': self.amount,
        })
    
    def sign_transaction(self):
        private_key = ECC.import_key(binascii.unhexlify(self.sender_private_key))
        signer = DSS.new(private_key, 'fips-186-3')
        h = SHA512.new(str(self.to_dict()).encode('utf-8'))
        signature = binascii.hexlify(signer.sign(h)).decode('ascii')
        return signature


app = Flask(__name__)

app.config['DOWNLOAD'] = "D:\\starkpay\\download"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/make-transaction')
def make_transaction():
    return render_template('make_trans.html')

@app.route('/transaction/generate', methods=['POST'])
def generate_transaction():
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    amount = request.form['amount']

    transaction = Transaction(sender_address, sender_private_key, recipient_address, amount)

    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transaction(),
    }

    return jsonify(response), 200

@app.route('/view-transactions')
def view_transactions():
    return render_template('view_trans.html')

@app.route('/new-wallet')
def new_wallet():
    # random_gen = Crypto.Random.new().read
    private_key = ECC.generate(curve='P-384')
    public_key = private_key.public_key()

    response = {
        'public_key': binascii.hexlify(public_key.export_key(format='DER')).decode('ascii'),
        'private_key': binascii.hexlify(private_key.export_key(format='DER')).decode('ascii'),
    }

    public_qr = pyqrcode.create(response['public_key'])
    public_qr.png("download/public_key.png", scale=10, module_color=(0, 255, 0, 255))
    private_qr = pyqrcode.create(response['private_key'])
    private_qr.png("download/private_key.png", scale=10, module_color=(255, 0, 0, 255))

    with open("download/public_key.txt", 'w') as public_txt:
        public_txt.write(response['public_key'])
    
    with open("download/private_key.txt", 'w') as private_txt:
        private_txt.write(response['private_key'])
    
    fromaddr = "ganesh.g.2018.cse@rajalakshmi.edu.in"
    toaddr = "ganeshgopi04@gmail.com"
    msg = MIMEMultipart()

    # storing the senders email address   
    msg['From'] = fromaddr 

    # storing the receivers email address  
    msg['To'] = toaddr 

    # storing the subject  
    msg['Subject'] = "Your Blockchain Wallet credentials"

    # string to store the body of the mail 
    body = "IMPORTANT\n\nSave your private and public keys. These keys cannot be recovered if lost!\nDon't share your private key with anyone!\n\nYour public and private keys are attatched in the following formats for convenience:\nQR Code images: public_key.png, private_key.png\nText files: public_key.txt, private_key.txt"

    # attach the body with the msg instance 
    msg.attach(MIMEText(body, 'plain')) 

    # open the file to be sent  
    filename1 = "public_key.png"
    attachment1 = open("download/public_key.png", "rb")
    filename2 = "private_key.png"
    attachment2 = open("download/private_key.png", "rb")
    filename3 = "public_key.txt"
    attachment3 = open("download/public_key.txt", "rb")
    filename4 = "private_key.txt"
    attachment4 = open("download/private_key.txt", "rb")

    # instance of MIMEBase and named as p 
    p = MIMEBase('application', 'octet-stream') 

    # To change the payload into encoded form 
    p.set_payload((attachment1).read()) 

    # encode into base64 
    encoders.encode_base64(p) 

    p.add_header('Content-Disposition', "attachment; filename= %s" % filename1) 

    # attach the instance 'p' to instance 'msg' 
    msg.attach(p)

    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment2).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename2)
    msg.attach(p)

    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment3).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename3)
    msg.attach(p)

    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment4).read())
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename4)
    msg.attach(p)
    # creates SMTP session 
    s = smtplib.SMTP('smtp.gmail.com', 587) 

    # start TLS for security 
    s.starttls() 

    # Authentication 
    s.login(fromaddr, "Q$F4dAJ7")

    # Converts the Multipart msg into a string 
    text = msg.as_string()

    # sending the mail 
    s.sendmail(fromaddr, toaddr, text) 

    # terminating the session 
    s.quit()

    return jsonify(response), 200

@app.route('/download/<file>')
def download(file):
    return send_from_directory(app.config['DOWNLOAD'], file)


if __name__ == '__main__':
    from argparse import ArgumentParser
    
    parser = ArgumentParser()

    parser.add_argument('-p', '--port', default=8080, type=int, help="Port number to listen.")
    args = parser.parse_args()
    port = args.port

    app.run(port=port, debug=True)
