# Copyright (c) 2024, hello@aerele.in and contributors
# For license information, please see license.txt
import frappe
from frappe.model.document import Document
from frappe.utils import flt, cstr
import rsa
from base64 import b64decode, b64encode
import json
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import requests
from Crypto.Util.Padding import unpad

import string, random

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
				"CREDITACC": payload.account_number ,
				"IFSC": payload.ifsc,
				"AMOUNT": cstr(payload.amount),
				"CURRENCY": "INR",
				"TXNTYPE": "TPA" if payload.bank == "ICICI Bank" else "RTG",
				"PAYEENAME": payload.account_name,
				"REMARKS": "Test RTGS",
				"WORKFLOW_REQD": "N"
			}
			frappe.log_error("Data - RTGS", data )
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

		url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment"

		headers = {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": connector_doc.get("ip_address") or "23.20.44.165",
			"host": "apibankingonesandbox.icicibank.com",
			"x-priority": "0010"
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

		response = requests.post(url, headers=headers, data=json.dumps(request_payload))
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
				elif response.STATUS == "DUPLICATE":
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
				else:
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
		else:
			res_dict.status = "Request Failure"
			if response.success == "false":
				res_dict.message = response.text
		frappe.log_error("Response message", response.text)
		return res_dict

	except Exception as e:
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

		data = {
			"AGGRID": connector_doc.aggr_id,
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.corp_usr,
			"URN": connector_doc.urn,
			"UNIQUEID": payload.name
		}

		frappe.log_error("Status - Data", data)

		bank_request_log_doc = frappe.new_doc("Bank Request Log")
		bank_request_log_doc.payload = json.dumps(data)
		bank_request_log_doc_name = bank_request_log_doc.insert().name
		frappe.db.commit()

		aes_key = "1234567887654321"
		aes_key_array = aes_key.encode("utf-8")

		encrypted_key = encrypt_key(aes_key_array, connector_doc)
		encrypted_data = encrypt_data(data, aes_key_array)

		url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-status"

		headers = {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": "23.20.44.165",
			"host": "apibankingonesandbox.icicibank.com",
			"x-priority": "0010"
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

		response = requests.post(url, headers=headers, data=json.dumps(request_payload))
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
					res_dict.status = "PENDING"
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
		frappe.log_error(frappe.get_traceback(), "Payment Status Traceback")
