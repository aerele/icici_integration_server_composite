// Copyright (c) 2024, hello@aerele.in and contributors
// For license information, please see license.txt

frappe.ui.form.on("ICICI Connector", {
	reset_endpoints(frm) {
        frappe.confirm(
            __("Are you sure you want to reset the endpoints to default values?"),
            // Yes callback
            function () {
                frm.call({
                    method: "reset_endpoints",
                    doc: frm.doc,
                    args: {
                        "update": true,
                    },
                    callback: function (r) {
                        if (r.message) {
                            frm.reload_doc();
                        }
                    },
                });
            },
            // No callback
            function () {
                frappe.msgprint(__("Reset action cancelled."));
            }
        );
    },
});

