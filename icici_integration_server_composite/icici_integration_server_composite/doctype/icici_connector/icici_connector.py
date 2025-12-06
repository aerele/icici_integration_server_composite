# Copyright (c) 2024, hello@aerele.in and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class ICICIConnector(Document):
	def get_url(self, action):
		base_url = self.base_url.rstrip("/")
		endpoint = frappe.get_value(
			"Endpoint URL",
			filters={"action": action, "parent": self.name},
			fieldname="url",
		)
		if not endpoint:
			frappe.throw(f"URL for action '{action}' not found in ICICI Connector {frappe.bold(self.name)}")

		url = endpoint.strip()
		if not url.startswith("http"):
			url = f"{base_url}/{url.lstrip('/')}"
	
		return url


	@frappe.whitelist()
	def reset_endpoints(self, update=False):
		default_endpoints = {
			"Make Payment": "/api/v1/composite-payment",
			"Get Status": "/api/v1/composite-status",
			"Get Balance": "/api/Corporate/CIB/v1/BalanceInquiry",
			"Get Statement": "/api/Corporate/CIB/v1/AccountStatement",
			"Get Statement Paginated": "/api/Corporate/CIB/v1/AccountStatements",
		}
		self.set("api_endpoints", [])
		for action, url in default_endpoints.items():
			self.append("api_endpoints", {"action": action, "url": url})

		if update:
			frappe.msgprint(frappe._("Endpoints have been reset to defaults in ICICI Connector {0}").format(frappe.bold(self.name)))
			self.save()
