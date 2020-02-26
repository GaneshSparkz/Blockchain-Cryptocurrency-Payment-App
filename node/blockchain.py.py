import binascii
import hashlib
import json
import requests

from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request
from flask_cors import CORS
from collections import OrderedDict
from time import time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA512
from uuid import uuid4
from urllib.parse import urlparse


MINING_SENDER = 'The Blockchain'
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        # Create the genesis block
        self.create_block(0, '00')

    def create_block(self, nonce, prev_hash):
        """
        Create a block of transactions
        """
        block = {
            'block_no': len(self.chain) + 1,
            'transactions': self.transactions,
            'timestamp': time(),
            'prev_hash': prev_hash,
            'nonce': nonce,
        }

        # Reset the current list of transactions
        self.transactions = []
        # Add the block to the chain
        self.chain.append(block)
        return block
    
    def hash(self, block):
        block_str = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_str)
        return h.hexdigest()
    
    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty
    
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['prev_hash'] != self.hash(last_block):
                return False
            transactions = block['transactions'][:-1]
            transaction_elements = ['sender_address', 'recipient_address', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]
            if not self.valid_proof(transactions, block['prev_hash'], block['nonce']):
                return False
            last_block = block
            current_index += 1
        
        return True
    
    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        
        if new_chain:
            self.chain = new_chain
            return True
        return False

    def verify_transaction_signature(self, sender_address, signature, transaction):
        public_key = ECC.import_key(binascii.unhexlify(sender_address))
        verifier = DSS.new(public_key, 'fips-186-3')
        h = SHA512.new(str(transaction).encode('utf-8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    def submit_transaction(self, sender_address, recipient_address, amount, signature):
        transaction = OrderedDict({
            'sender_address': sender_address,
            'recipient_address': recipient_address,
            'amount': amount,
        })

        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            signature_valid = self.verify_transaction_signature(sender_address, signature, transaction)
            if signature_valid:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False
    
    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        
        return nonce
    
    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("Invalid URL")


blockchain = Blockchain()

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/configure')
def configure():
    return render_template('config.html')

@app.route('/transactions/get')
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200

@app.route('/mine')
def mine():
    if len(blockchain.transactions) == 0:
        response = {
            'message': 'No available transactions to mine'
        }

        return jsonify(response), 400
    
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(
        sender_address=MINING_SENDER,
        recipient_address=blockchain.node_id,
        amount=MINING_REWARD,
        signature=''
    )

    last_block = blockchain.chain[-1]
    prev_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, prev_hash)

    response = {
        'message': 'New Block created',
        'block_no': block['block_no'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'prev_hash': block['prev_hash'],
    }

    return jsonify(response), 200

@app.route('/chain/get')
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }

    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    sender_address = request.form['confirmation_sender_public_key']
    recipient_address = request.form['confirmation_recipient_public_key']
    amount = request.form['confirmation_amount']
    signature = request.form['transaction_signature']

    required = [
        'confirmation_sender_public_key',
        'confirmation_recipient_public_key',
        'confirmation_amount',
        'transaction_signature',
    ]
    if not all(k in request.form for k in required):
        return 'Missing values', 400

    result = blockchain.submit_transaction(sender_address, recipient_address, amount, signature)

    if not result:
        response = {'message': 'Invalid transaction'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to block ' + str(result)}
        return jsonify(response), 201

@app.route('/nodes/get')
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.form
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400
    
    for node in nodes:
        blockchain.register_node(node)
    
    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }

    return jsonify(response), 200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    
    parser = ArgumentParser()

    parser.add_argument('-p', '--port', default=5000, type=int, help="Port number to listen.")
    args = parser.parse_args()
    port = args.port

    app.run(port=port, debug=True)
