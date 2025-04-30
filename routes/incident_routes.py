# sec_dashboard/routes/incident_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response
from models import db, IODEFDocument
import requests

incident_bp = Blueprint("incident_bp", __name__)

@incident_bp.route("/incident/<int:doc_id>")
def incident_detail(doc_id):
    incident = IODEFDocument.query.get_or_404(doc_id)
    return render_template("incident_detail.html", incident=incident)

@incident_bp.route("/latest-incidents")
def latest_incidents():
    incidents = IODEFDocument.query.order_by(IODEFDocument.created_at.desc()).limit(20).all()
    return render_template("latest_incidents.html", incidents=incidents)

@incident_bp.route("/iodef-documents/<int:doc_id>")
def show_iodef_documents(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    return f"<h3>Incident ID: {doc.incidentid}</h3><pre style='background:#eee; padding:15px; direction:ltr'>{doc.raw_xml}</pre>"

@incident_bp.route("/iodef-documents/download/<int:doc_id>")
def download_iodef_document(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    response = make_response(doc.raw_xml)
    response.headers["Content-Type"] = "application/xml"
    response.headers["Content-Disposition"] = f"attachment; filename={doc.incidentid}.xml"
    return response

@incident_bp.route("/iodef-documents/edit/<int:doc_id>", methods=["GET", "POST"])
def edit_iodef_document(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    if request.method == "POST":
        doc.raw_xml = request.form["xml"]
        db.session.commit()
        flash("XML updated!", "success")
        return redirect(url_for("incident_bp.incident_detail", doc_id=doc.id))
    return render_template("edit_iodef.html", doc=doc)

@incident_bp.route("/incident/resend/<int:doc_id>", methods=["POST"])
def resend_iodef_document(doc_id):
    incident = IODEFDocument.query.get_or_404(doc_id)
    try:
        response = requests.post("httpbin.org/post", data=incident.raw_xml,
                                 headers={'Content-Type': 'application/xml'})
        flash(f"📤 ارسال مجدد با موفقیت انجام شد. (Status: {response.status_code})", "success")
    except Exception as e:
        flash(f"خطا در ارسال مجدد: {str(e)}", "error")
    return redirect(url_for("incident_bp.incident_detail", doc_id=doc_id))

@incident_bp.route("/iodef/view/<int:incident_id>")
def view_iodef_document(incident_id):
    incident = IODEFDocument.query.get_or_404(incident_id)
    return render_template("show_incident.html", incident=incident)

@incident_bp.route("/api/latest-iodef")
def latest_iodef():
    docs = (IODEFDocument.query
            .order_by(IODEFDocument.created_at.desc())
            .limit(10).all())
    return jsonify([{
        "id": d.id,
        "incidentid": d.incidentid,
        "created_at": d.created_at.strftime("%Y-%m-%d %H:%M")
    } for d in docs])
