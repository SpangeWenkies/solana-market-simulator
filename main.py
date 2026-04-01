# create JSON holding transactions
# create chain that stores subsequent blocks
# create proof of stake algorithm
# create a way to add new transactions to the chain
# create a way to verify the chain is valid
# create a way to resolve conflicts between chains
# create a web app to interact with the blockchain
# create a way to register nodes in the network
# create a way to reach consensus between nodes
# create a random transaction request loop to test the blockchain
# create transaction data using benford's law to simulate real-world transactions

import hashlib
import json
import time
from uuid import uuid4
from flask import Flask, jsonify, request
from urllib.parse import urlparse
import requests
