# routes/iodef.py

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, make_response
from models import db, IODEFDocument, SplunkAlert
import os
import requests

iodef_bp = Blueprint("iodef_bp", __name__)

basedir = os.path.abspath(os.path.dirname(__file__))

@iodef_bp.route("/splunk-hook", methods=["POST"])
def splunk_hook():
    try:
        data = request.get_json(force=True)
        src         = data.get("src") or ""
        dest        = data.get("dest") or ""
        counter_raw = data.get("counter") or "0"
        starttime   = data.get("starttime") or ""
        endtime     = data.get("endtime") or ""
        detecttime  = data.get("detecttime") or ""
        reporttime  = data.get("reporttime") or ""
        body        = data.get("body") or ""
        incidentid  = data.get("incidentid") or ""

        if not incidentid:
            return jsonify(error="incidentid الزامی است"), 400

        if IODEFDocument.query.filter_by(incidentid=incidentid).first():
            return jsonify(error="incidentid تکراری است"), 409

        try:
            counter = int(counter_raw)
        except:
            counter = 0

        iodeftype = "dos" if counter > 1000 else "scan"
        iodefdescription = f"حمله از {src} به {dest} با {counter} تلاش." if src and dest else "هشدار Splunk"

        template_path = os.path.join(os.path.dirname(basedir), "main_body.txt")
        with open(template_path, encoding="utf-8") as f:
            xml_template = f.read()

        xml_filled = (
            xml_template
            .replace("+ incidentid +", incidentid)
            .replace("+ detecttime +", detecttime)
            .replace("+ starttime +", starttime)
            .replace("+ endtime +", endtime)
            .replace("+ reporttime +", reporttime)
            .replace("+ iodefdescription +", iodefdescription)
            .replace("+ iodeftype +", iodeftype)
            .replace("+ src +", src)
            .replace("+ counter +", str(counter))
        )

        alert = SplunkAlert(
            src=src, dest=dest, counter=counter,
            starttime=starttime, endtime=endtime,
            detecttime=detecttime, reporttime=reporttime,
            body=body, incidentid=incidentid,
            iodefdescription=iodefdescription, iodeftype=iodeftype
        )
        db.session.add(alert)

        xml_doc = IODEFDocument(incidentid=incidentid, raw_xml=xml_filled)
        db.session.add(xml_doc)

        db.session.commit()

        DEST_URL = "http://192.168.1.100:8000/upload"
        try:
            resp = requests.post(
                DEST_URL,
                data=xml_filled,
                headers={"Content-Type": "application/xml"},
                timeout=10
            )
            status = resp.status_code
        except requests.RequestException as e:
            status = f"network‑error ⇒ {e}"

        return jsonify(message="ذخیره شد", forward_status=status), 201

    except Exception as e:
        db.session.rollback()
        return jsonify(error=str(e)), 500


@iodef_bp.route("/iodef-documents")
def view_iodef_documents():
    documents = IODEFDocument.query.order_by(IODEFDocument.created_at.desc()).all()
    return render_template("view_iodef_documents.html", documents=documents)

@iodef_bp.route("/iodef-documents/<int:doc_id>")
def show_iodef_documents(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    return f"<h3>Incident ID: {doc.incidentid}</h3><pre style='background:#eee; padding:15px; direction:ltr'>{doc.raw_xml}</pre>"

@iodef_bp.route("/iodef-documents/download/<int:doc_id>")
def download_iodef_document(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    response = make_response(doc.raw_xml)
    response.headers["Content-Type"] = "application/xml"
    response.headers["Content-Disposition"] = f"attachment; filename={doc.incidentid}.xml"
    return response

@iodef_bp.route("/iodef-documents/edit/<int:doc_id>", methods=["GET", "POST"])
def edit_iodef_document(doc_id):
    doc = IODEFDocument.query.get_or_404(doc_id)
    if request.method == "POST":
        doc.raw_xml = request.form["xml"]
        db.session.commit()
        flash("XML بروزرسانی شد", "success")
        return redirect(url_for("iodef_bp.view_iodef_documents"))
    return render_template("edit_iodef.html", doc=doc)
