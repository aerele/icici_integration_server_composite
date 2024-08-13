# Copyright (c) 2024, hello@aerele.in and contributors
# For license information, please see license.txt
import frappe
from frappe.model.document import Document
from frappe.utils import flt, cstr
import rsa
from base64 import b64decode, b64encode
import json
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES, PKCS1_v1_5
import requests
from Crypto.Util.Padding import unpad

from Crypto.PublicKey import RSA
import base64

import string, random

bank_balance_url = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/BalanceInquiry"
payment_status_url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-status"
make_payment_url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment"
bank_statement_url_paginated = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/AccountStatements"

class BankRequestLog(Document):
	pass

IV = "0000000000000000".encode("utf-8")
BLOCK_SIZE = 16

def get_decrypted_response(connector_doc, response=None):
	if response:
		response=json.loads(response.text)
		decrypted_key=decrypt_key(response.get("encryptedKey"), connector_doc)
		decrypted_data = decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
		return decrypted_data

def decrypt_data(data, key):
	message = b64decode(data)

	cipher= AES.new(key, AES.MODE_CBC, IV)
	decrypted = cipher.decrypt(message)

	unpaded = unpad(decrypted, BLOCK_SIZE)

	return json.loads(unpaded[BLOCK_SIZE:])

def decrypt_key(key, connector_doc):
#	private_key_file_path = "/home/frappe/frappe-bench/privkey_rsa.pem"
	private_key_file_path = frappe.get_doc("File", {"file_url": connector_doc.private_key}).get_full_path()
	frappe.log_error("private_key_file_path", private_key_file_path)

	with open(private_key_file_path, 'rb') as p:
		private_key = rsa.PrivateKey.load_pkcs1(p.read())
		decrypted_key = rsa.decrypt(b64decode(key), private_key).decode('utf-8')
		return decrypted_key

def get_id():
	return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))

def encrypt_data(data, key):
	data = json.dumps(data)
	# convert to bytes
	byte_array = data.encode("utf-8")
	# pad the message - with pkcs5 style
	padded = pad(byte_array, BLOCK_SIZE)
	# new instance of AES with encoded key

	cipher = AES.new(key, AES.MODE_CBC, IV)
	# now encrypt the padded bytes
	encrypted = cipher.encrypt(padded)
	#append with IV
	# print(IV)
	# print(encrypted)
	encrypted_with_iv = encrypted
	# base64 encode and convert back to string
	return  b64encode(encrypted_with_iv).decode('utf-8')

def encrypt_key(key, connector_doc):
#	bank_public_key_file_path = "/home/frappe/frappe-bench/icici_cert_composite_rsa.pem"
	bank_public_key_file_path = frappe.get_doc("File", {"file_url": connector_doc.bank_public_key}).get_full_path()

	with open(bank_public_key_file_path, "rb") as p:
		public_key = rsa.PublicKey.load_pkcs1(p.read())
		encrypted_key = rsa.encrypt(key, public_key)
		return b64encode(encrypted_key).decode('utf-8')

def get_priority(mode_of_transfer):
	if mode_of_transfer == "RTGS":
		return "0001"
	elif mode_of_transfer == "IMPS":
		return "0100"
	else:
		return "0010"

@frappe.whitelist()
def make_payment(payload):
	try:
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

		if isinstance(payload, str):
			payload = json.loads(payload)

		payload = frappe._dict(payload)
		payment_doc = frappe._dict(payload.doc)

		connector_doc = frappe.get_doc("ICICI Connector", payment_doc.company_account_number)

		if not connector_doc:
			frappe.throw(f"Connector for account number {payment_doc.company_account_number} not found.")

		data = {}
		if payload.mode_of_transfer == "RTGS":
			data = {
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"AGGRNAME": connector_doc.aggr_name,
				"UNIQUEID": payload.name,
				"DEBITACC": connector_doc.account_number,
				"CREDITACC": payload.bank_account_no,
				"IFSC": payload.branch_code,
				"AMOUNT": cstr(payload.amount),
				"CURRENCY": "INR",
				"TXNTYPE": "TPA" if payload.bank == "ICICI Bank" else "RTG",
				"PAYEENAME": payload.account_name,
				"REMARKS": "Test RTGS",
				"WORKFLOW_REQD": "N"
			}
			frappe.log_error("Data - RTGS", data )

		elif payload.mode_of_transfer == "IMPS":
			if not connector_doc.enable_imps:
				res_dict = frappe._dict({})
				res_dict.status = "Request Failure"
				res_dict.message = "IMPS is not enabled for this {} account.".format(connector_doc.account_number)
				return
			data ={
				"localTxnDtTime": frappe.utils.now_datetime().strftime("%Y%m%d%H%M%S"),
				"beneAccNo": payload.bank_account_no,
				"beneIFSC": payload.branch_code,
				"amount": cstr(payload.amount),
				"tranRefNo": payload.name,
				"paymentRef": payload.name,
				"senderName": payment_doc.company_bank_account_name,
				"mobile": payment_doc.mobile_number,
				"retailerCode": connector_doc.retailer_code,
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid,
				"aggrId": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr
				}

			frappe.log_error("Data - IMPS", data )
		else:
			data = {
				"tranRefNo": payload.name,
				"amount": cstr(payload.amount),
				"senderAcctNo": connector_doc.account_number,
				"beneAccNo": payload.bank_account_no,
				"beneName": payload.account_name,
				"beneIFSC": payload.branch_code,
				"narration1": payload.party_name,
				"narration2": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr,
				"aggrId": connector_doc.aggr_id,
				"urn": connector_doc.urn,
				"aggrName": connector_doc.aggr_name,
				"txnType": "TPA" if payload.bank == "ICICI Bank" else "RTG",
				"WORKFLOW_REQD": "N"
			}
			frappe.log_error("Data - NEFT", data )

		frappe.log_error(data.get('txnType'))

		bank_request_log_doc = frappe.new_doc("Bank Request Log")
		bank_request_log_doc.payload = json.dumps(data)
		bank_request_log_doc_name = bank_request_log_doc.insert().name

		aes_key = "1234567887654321"
		aes_key_array = aes_key.encode("utf-8")

		encrypted_key = encrypt_key(aes_key_array, connector_doc)
		encrypted_data = encrypt_data(data, aes_key_array)

		headers = {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": connector_doc.get("ip_address") or "23.20.44.165",
			"host": "apibankingonesandbox.icicibank.com",
			"x-priority": get_priority(payload.mode_of_transfer)
		}
		frappe.log_error("headers", headers )

		request_payload = {
			"requestId": payload.name,
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": b64encode(IV).decode("utf-8")
		}
		frappe.log_error("request_payload", request_payload)

		res_dict = frappe._dict({})

		response = requests.post(make_payment_url, headers=headers, data=json.dumps(request_payload))
		frappe.db.set_value("Bank Request Log", bank_request_log_doc_name, "status_code", response.status_code)

		frappe.log_error("response body", response.request.body)
		frappe.log_error("response headers", response.request.headers)

		if response.ok:
			decrypted_response= get_decrypted_response(connector_doc, response)
			res_dict.response = decrypted_response
			frappe.log_error("Decrypted Response", decrypted_response)
			if decrypted_response:
				if isinstance(decrypted_response, str):
					decrypted_response =json.loads(decrypted_response)

				response= frappe._dict(decrypted_response)
				if response.STATUS == "SUCCESS":
					res_dict.status = "ACCEPTED"
					res_dict.message = response.MESSAGE
				elif response.STATUS == "PENDING":
					res_dict.status = "ACCEPTED"
					res_dict.message = response.MESSAGE
				elif response.STATUS == "DUPLICATE":
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
				elif  response.errorCode == "997":
					res_dict.status = "Request Failure"
					res_dict.message = response.errorCode + " : " + response.description
				else:
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or ""

		frappe.log_error("Response message", response.text)
		return res_dict

	except Exception as e:
		res_dict = frappe._dict({})
		res_dict.status = "Request Failure"
		res_dict.message = frappe.get_traceback()

		frappe.log_error(frappe.get_traceback(), "Payment Traceback")

#Payment Status
@frappe.whitelist()
def get_payment_status(payload):
	try:
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

		if isinstance(payload, str):
			payload = json.loads(payload)
		payload = frappe._dict(payload)

		payment_doc = frappe._dict(payload.doc)

		connector_doc = frappe.get_doc("ICICI Connector", payment_doc.company_account_number)

		if not connector_doc:
			frappe.throw(f"Connector for account number {payment_doc.company_account_number} not found.")
		if payload.mode_of_transfer == "IMPS":
			data = {
				"transRefNo": payload.name,
				"date": payload.payment_date,
				"recon360": "N",
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid
				}
		else:
			data = {
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"UNIQUEID": payload.name
			}

		frappe.log_error(f"Status {payload.mode_of_transfer} - Data", data)

		bank_request_log_doc = frappe.new_doc("Bank Request Log")
		bank_request_log_doc.payload = json.dumps(data)
		bank_request_log_doc_name = bank_request_log_doc.insert().name
		frappe.db.commit()

		aes_key = "1234567887654321"
		aes_key_array = aes_key.encode("utf-8")

		encrypted_key = encrypt_key(aes_key_array, connector_doc)
		encrypted_data = encrypt_data(data, aes_key_array)

		headers = {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": "23.20.44.165",
			"host": "apibankingonesandbox.icicibank.com",
			"x-priority": get_priority(payload.mode_of_transfer)
		}
		frappe.log_error("status - header", headers)

		request_payload = {
			"requestId": payload.name,
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": b64encode(IV).decode("utf-8")
		}
		frappe.log_error("status - request_payload", request_payload)

		response = requests.post(payment_status_url, headers=headers, data=json.dumps(request_payload))
		frappe.db.set_value("Bank Request Log", bank_request_log_doc_name, "status_code", response.status_code)

		frappe.log_error("response body", response.request.body)
		frappe.log_error("response headers", response.request.headers)

		res_dict = frappe._dict({})

		if response.ok:
			decrypted_response= get_decrypted_response(connector_doc, response)
			frappe.log_error("decrypted_response", decrypted_response)

			res_dict.decrypted_response = decrypted_response
			if decrypted_response:
				response = frappe._dict(decrypted_response)
				if response.STATUS == "SUCCESS":
					res_dict.status = "Processed"
					res_dict.reference_number = response.UTRNUMBER
					res_dict.message = "Success"
				elif response.STATUS == "PENDING":
					res_dict.status = "Pending"
					res_dict.message = response.MESSAGE
				else:
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text

		frappe.log_error("Payment response message", response.text)
		return res_dict
	except Exception as e:
		res_dict.status = "Request Failure"
		res_dict.message = frappe.get_traceback()

		frappe.log_error(frappe.get_traceback(), "Payment Status Traceback")
		return res_dict

def get_encrypted_request(data, connector_doc):
	source = json.dumps(data)

	public_key_path = frappe.get_doc("File", {"file_url": connector_doc.bank_public_key}).get_full_path()
	public_key = open(public_key_path, "r")
	key = RSA.importKey(public_key.read())

	cipher = PKCS1_v1_5.new(key)
	cipher_text = cipher.encrypt(source.encode())
	cipher_text = base64.b64encode(cipher_text)
	return cipher_text

def get_decrypted_response_aysnc(response, connector_doc):
	private_key_path = frappe.get_doc("File", {"file_url": connector_doc.private_key}).get_full_path()
	public_key = open(private_key_path, "r")
	cipher = PKCS1_v1_5.new(private_key.read())

	try:
		raw_cipher_data = base64.b64decode(response.content)
	except:
		raise Exception(f"Invalid Response {response.content}")

	decrypted_res = cipher.decrypt(raw_cipher_data, b'x')
	decrypted_res = decrypted_res.decode("utf-8")
	return json.loads(decrypted_res)

@frappe.whitelist()
def get_bank_balance(payload):
	if not frappe.has_permission("Bank Request Log", "write"):
		frappe.throw("Not permitted", frappe.PermissionError)

	if isinstance(payload, str):
		payload = json.loads(payload)

	payload = frappe._dict(payload)

	connector_doc = frappe.get_doc("ICICI Connector", payload.bank_account_number)

	if not connector_doc:
		frappe.throw(f"Connector for account number {payload.bank_account_number} not found")
	

	headers = {
		"accept": "*/*",
		"content-type": "text/plain",
		"apikey": connector_doc.get_password("api_key"),
		"x-forwarded-for": connector_doc.ip_address or "52.140.62.166"
	}

	data = {
			"AGGRID": connector_doc.aggr_id,
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.payment_status_checker_user_id or connector_doc.payment_creator_user_id,
			"URN":connector_doc.urn,
			"ACCOUNTNO": payload.company_account_number
	}

	res_dict = frappe._dict({})

	try:
		response = requests.post(bank_balance_url, headers=headers, data=get_encrypted_request(data, connector_doc))
		if response.ok:
			try:
				decrypted_response = get_decrypted_response_aysnc(response, connector_doc)

				res_dict.res_text = decrypted_response
				res_dict.res_status = response.status_code
				res_dict.api_method = "get_bank_balance"
				res_dict.config_details = data
				if 'EFFECTIVEBAL' in decrypted_response and decrypted_response['EFFECTIVEBAL']:
					res_dict.server_status="Success"
					res_dict.balance = decrypted_response['EFFECTIVEBAL']
			except:
				res_dict.server_status="Failed"
				res_dict.res_text = response.text
				frappe.log_error(title="get_bank_balance - API Response", message= frappe.get_traceback())

		else:
			res_dict.res_text = response.text
			res_dict.res_status = response.status_code
			res_dict.api_method = "get_bank_balance"
			res_dict.config_details = data
			res_dict.server_status="Failed"
	except:
		res_dict.server_status="Failed"
		res_dict.res_text = response.text
		frappe.log_error(title="make_payment - API Response", message= frappe.get_traceback())

	return res_dict

def load_rsa_keys(connector_doc):
	public_key_path = frappe.get_doc("File", {"file_url": connector_doc.bank_public_key}).get_full_path()
	private_key_path = frappe.get_doc("File", {"file_url": connector_doc.private_key}).get_full_path()

	with open(public_key_path, 'rb') as public_file:
		public_key = RSA.import_key(public_file.read())

	with open(private_key_path, 'rb') as private_file:
		private_key = RSA.import_key(private_file.read())

	return public_key, private_key
   
# Encrypt data using RSA public key
def rsa_encrypt(data, public_key):
	cipher = PKCS1_v1_5.new(public_key)
	encrypted_data = cipher.encrypt(data.encode())
	# cipher = PKCS1_OAEP.new(public_key)
	# encrypted_data = cipher.encrypt(data.encode())
	return encrypted_data

# Decrypt data using RSA private key
def rsa_decrypt(encrypted_data, private_key):
	cipher = PKCS1_v1_5.new(private_key)
	decrypted_data = cipher.decrypt(encrypted_data, None)
	return decrypted_data.decode('utf-8')
   
def decrypt_account_statement(connector_doc, encrypted_key, encrypted_data):
	try:
		# Load the client's RSA private key
		public_key, private_key = load_rsa_keys(connector_doc)
 
		# Step 1: Decrypting the encrypted key using client private key
		decoded_encrypted_key = base64.b64decode(encrypted_key)
		session_key = rsa_decrypt(decoded_encrypted_key, private_key)
		# Step 2: Base64 decode encrypted data
		decoded_data = base64.b64decode(encrypted_data)
 
		# Step 3: Retrieving iv from the first 16 characters of decoded data
		iv = decoded_data[:16]
 
		# Step 4: Doing symmetric key decryption on encrypted data
		cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv)
		decrypted_data = cipher.decrypt(decoded_data[16:])
 
		# Remove PKCS5 padding
		unpad = lambda s: s[:-ord(s[len(s)-1:])]
		account_statement = unpad(decrypted_data)
 
		return account_statement.decode('utf-8')
 
	except Exception as e:
		print('Decryption Error:', str(e))
		return None

@frappe.whitelist()
def get_bank_statement(payload):
	if not frappe.has_permission("Bank Request Log", "write"):
		frappe.throw("Not permitted", frappe.PermissionError)

	if isinstance(payload, str):
		payload = json.loads(payload)

	payload = frappe._dict(payload)

	connector_doc = frappe.get_doc("ICICI Connector", payload.bank_account_number)

	if not connector_doc:
		frappe.throw(f"Connector for account number {payload.bank_account_number} not found")

	headers = {
		"accept": "*/*",
		"content-type": "text/plain",
		"apikey": connector_doc.get_password("api_key"),
		"x-forwarded-for": connector_doc.ip_address or "52.140.62.166"
	}

	res_dict = frappe._dict({})

	try:
		# Define the request payload for the account statement
		request_payload = {
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.payment_status_checker_user_id or connector_doc.payment_creator_user_id,
			"AGGRID": connector_doc.aggr_id,
			"ACCOUNTNO": payload.company_account_number,
			"FROMDATE": payload.from_date,
			"TODATE": payload.to_date,
			"URN": connector_doc.urn,
			"CONFLG": 'Y' if payload.conflg else 'N'
		}

		if payload.last_trid:
			request_payload["LASTTRID"] = payload.last_trid
 
		# Serialize the request payload to JSON
		request_payload_json = json.dumps(request_payload)
 
		# Load the client's RSA private key
		public_key, private_key = load_rsa_keys(connector_doc)
 
		# Encrypt the request payload
		encrypted_payload = rsa_encrypt(request_payload_json, public_key)
 
		# Encode the encrypted payload to base64
		base64_encoded_payload = base64.b64encode(encrypted_payload).decode()
 
		# Make the API request
		response = requests.post(bank_statement_url_paginated, data=base64_encoded_payload, headers=headers)
 
		response_data = response.json()
		encrypted_key = response_data.get('encryptedKey')
		encrypted_data = response_data.get('encryptedData')

		# Decrypt the account statement using the decryption function
		decrypted_statement = None
		if encrypted_key and encrypted_data:
			decrypted_statement = decrypt_account_statement(connector_doc, encrypted_key.encode('utf-8'), encrypted_data.encode('utf-8'))
		
		if decrypted_statement:
			if "Record" in decrypted_statement:
				res_dict.res_text = decrypted_statement
				res_dict.res_status = response.status_code
				res_dict.api_method = "get_bank_statements"
				res_dict.config_details = request_payload
				res_dict.server_status="Success"
				if isinstance(decrypted_statement.get('Record'), list):
					res_dict.bank_statements = json.dumps(decrypted_statement.get('Record'))
				else:
					res_dict.bank_statements = decrypted_statement.get('Record')
			else:
				res_dict.res_text = "No records found in the response"
				res_dict.res_status = response.status_code
				res_dict.api_method = "get_bank_statements"
				res_dict.config_details = request_payload
				res_dict.server_status="Success"
		else:
			res_dict.res_status = response.status_code
			res_dict.api_method = "get_bank_statements"
			res_dict.config_details = request_payload
			res_dict.server_status="Failed"
 
	except:
		res_dict.api_method = "get_bank_statements"
		res_dict.config_details = request_payload
		res_dict.server_status="Failed"
		res_dict.message = frappe.get_traceback()
	
	return res_dict
