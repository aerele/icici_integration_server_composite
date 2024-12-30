# Copyright (c) 2024, hello@aerele.in and contributors
# For license information, please see license.txt
from frappe.model.document import Document
from frappe.utils import flt, cstr
import string, random
import requests
import frappe
import json

from base64 import b64decode, b64encode
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA

from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
import base64
import rsa

from requests.models import Response


payment_status_url = "https://apibankingone.icicibank.com/api/v1/composite-status"
make_payment_url = "https://apibankingone.icicibank.com/api/v1/composite-payment"

bank_balance_url = "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/BalanceInquiry"
bank_statement_url = "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/AccountStatement"
bank_statement_url_paginated = "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/AccountStatements"

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
	private_key_file_path = frappe.get_doc("File", {"file_url": connector_doc.private_key}).get_full_path()

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
	encrypted_with_iv = encrypted
	# base64 encode and convert back to string
	return  b64encode(encrypted_with_iv).decode('utf-8')

def encrypt_key(key, connector_doc):
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
		if not payload.remarks:
			payload.remarks = ""
		if payload.mode_of_transfer == "RTGS":
			data = {
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"AGGRNAME": connector_doc.aggr_name,
				"UNIQUEID": str(payload.name),
				"DEBITACC": connector_doc.account_number,
				"CREDITACC": payload.bank_account_no,
				"IFSC":  connector_doc.ifsc_code if payload.bank == "ICICI Bank" else payload.branch_code,
				"AMOUNT": cstr(payload.amount),
				"CURRENCY": "INR",
				"TXNTYPE": "TPA" if payload.bank == "ICICI Bank" else "RTG",
				"PAYEENAME": payload.account_name,
				"REMARKS": payload.remarks[:50],
				"WORKFLOW_REQD": "Y"
			}

		elif payload.mode_of_transfer == "IMPS":
			if not connector_doc.enable_imps:
				res_dict = frappe._dict({})
				res_dict.status = "Request Failure"
				res_dict.message = "IMPS is not enabled for this {} account.".format(connector_doc.account_number)
				return res_dict
			data ={
				"localTxnDtTime": frappe.utils.now_datetime().strftime("%Y%m%d%H%M%S"),
				"beneAccNo": payload.bank_account_no,
				"beneIFSC": connector_doc.ifsc_code if payload.bank == "ICICI Bank" else payload.branch_code,
				"amount": cstr(payload.amount),
				"tranRefNo":  str(payload.name),
				"paymentRef":  payload.remarks[:50],
				"senderName": payment_doc.company_bank_account_name,
				"mobile": payment_doc.mobile_number,
				"retailerCode": connector_doc.retailer_code,
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid,
				"aggrId": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr
				}

		else:
			data = {
				"tranRefNo":  str(payload.name),
				"amount": cstr(payload.amount),
				"senderAcctNo": connector_doc.account_number,
				"beneAccNo": payload.bank_account_no,
				"beneName": payload.account_name,
				"beneIFSC": connector_doc.ifsc_code if payload.bank == "ICICI Bank" else payload.branch_code,
				"narration1": payload.party_name,
				"narration2": payload.remarks[:50],
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr,
				"aggrId": connector_doc.aggr_id,
				"urn": connector_doc.urn,
				"aggrName": connector_doc.aggr_name,
				"txnType": "TPA" if payload.bank == "ICICI Bank" else "RGS",
				"WORKFLOW_REQD": "Y"
			}

		aes_key = "1234567887654321"
		aes_key_array = aes_key.encode("utf-8")

		encrypted_key = encrypt_key(aes_key_array, connector_doc)
		encrypted_data = encrypt_data(data, aes_key_array)

		headers = {
			"accept": "*/*",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": connector_doc.get("ip_address", ''),
			"host": "apibankingone.icicibank.com",
			"content-length": "684",
			"x-priority": get_priority(payload.mode_of_transfer)
		}

		request_payload = {
			"requestId":  str(payload.name),
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": b64encode(IV).decode("utf-8")
		}

		res_dict = frappe._dict({})

		response = requests.post(make_payment_url, headers=headers, data=json.dumps(request_payload))

		log_name = create_api_log(response, 'Initiate Payment', payload.parenttype, payload.parent, data)

		if response.ok:
			decrypted_response= get_decrypted_response(connector_doc, response)
			res_dict.response = decrypted_response
			if log_name:
				frappe.db.set_value("Bank Request Log",log_name, "decrypted_response", json.dumps(decrypted_response))

			if decrypted_response:
				if isinstance(decrypted_response, str):
					decrypted_response =json.loads(decrypted_response)

				decrypted_response= frappe._dict(decrypted_response)
				if decrypted_response.STATUS == "SUCCESS":
					res_dict.status = "ACCEPTED"
					res_dict.message = decrypted_response.MESSAGE
				elif decrypted_response.STATUS == "PENDING":
					res_dict.status = "ACCEPTED"
					res_dict.message = decrypted_response.MESSAGE
				elif decrypted_response.STATUS == "DUPLICATE":
					res_dict.status = "FAILURE"
					res_dict.message = decrypted_response.MESSAGE
				elif  decrypted_response.errorCode == "997":
					res_dict.status = "Request Failure"
					res_dict.message = decrypted_response.errorCode + " : " + decrypted_response.description
				else:
					res_dict.status = "FAILURE"
					res_dict.message = decrypted_response.MESSAGE
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or ""

		return res_dict

	except Exception as e:
		res_dict = frappe._dict({})
		res_dict.status = "Request Failure"
		res_dict.message = frappe.get_traceback()

		frappe.log_error( "Payment Traceback", frappe.get_traceback())
		return res_dict

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
				"transRefNo":  str(payload.name),
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
				"UNIQUEID":  str(payload.name)
			}

		aes_key = "1234567887654321"
		aes_key_array = aes_key.encode("utf-8")

		encrypted_key = encrypt_key(aes_key_array, connector_doc)
		encrypted_data = encrypt_data(data, aes_key_array)

		headers = {
			"accept": "*/*",
			"content-type": "application/json",
			"apikey": connector_doc.get_password("api_key"),
			"x-forwarded-for": connector_doc.get("ip_address", ''),
			"host": "apibankingone.icicibank.com",
			"content-length": "684",
			"x-priority": get_priority(payload.mode_of_transfer)
		}

		request_payload = {
			"requestId":  str(payload.name),
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": b64encode(IV).decode("utf-8")
		}

		response = requests.post(payment_status_url, headers=headers, data=json.dumps(request_payload))

		log_name = create_api_log(response, 'Payment Status', payload.parenttype, payload.parent, data)

		res_dict = frappe._dict({})

		if response.ok:
			decrypted_response= get_decrypted_response(connector_doc, response)
			if log_name:
				frappe.db.set_value("Bank Request Log", log_name, "decrypted_response", json.dumps(decrypted_response))

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

		return res_dict
	except Exception as e:
		res_dict = frappe._dict({})
		res_dict.status = "Request Failure"
		res_dict.message = frappe.get_traceback()

		frappe.log_error("Payment Status traceback", frappe.get_traceback())
		return res_dict


@frappe.whitelist()
def create_api_log(res, action= None, ref_doctype= None, ref_docname= None, config_details=None):
	"""Can create API log From response

	Args:
		res (response object): It is used to obtain an API response.
		request_from (str): It is optional for the purposes of the API...
	"""
	if not isinstance(res, Response): return

	try:
		log_doc = frappe.new_doc("Bank Request Log")
		log_doc.action = action
		log_doc.url = res.request.url
		log_doc.method = res.request.method

		try:
			log_doc.payload =json.dumps(res.request.body, indent=4)
			log_doc.response = json.dumps(res.json(), indent=4)
			log_doc.config_details = json.dumps(config_details, indent=4)
		except:
			log_doc.response = res.text
			frappe.log_error(title='Error in creating API Log', message=frappe.get_traceback())

		log_doc.status_code = res.status_code
		log_doc.ref_doctype = ref_doctype
		log_doc.ref_document = ref_docname
		log_doc.save()
		return log_doc.name
	except:
		frappe.log_error(title='Error in creating API Log', message=frappe.get_traceback())
	else:
		frappe.db.commit()