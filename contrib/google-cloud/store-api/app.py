import asyncio
import os
import uuid
from datetime import datetime

from google.cloud import firestore
from hypercorn.asyncio import serve
from hypercorn.config import Config
from quart import Quart, json, request

from config import *

db = firestore.Client()

app = Quart(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/healthcheck")
async def healthcheck():
    return "ok"


@app.route("/summary", methods=["GET", "DELETE", "POST"])
async def handle_summary():
    if request.method in ("GET", "DELETE"):
        args = request.args
        if not args:
            return "Not Found", 404
        db_ref = db.collection(SUMMARY_COLLECTION)
        id = request.args.get("id")
        if id:
            doc_ref = db_ref.document(id)
            doc = doc_ref.get()
            if doc.exists:
                if request.method == "DELETE":
                    doc_ref.delete()
                    return {"success": "true"}
                return {
                    "success": "true",
                    "response": {"id": doc.id, "data": doc.to_dict()},
                }
    elif request.method in ["POST"]:
        req_json = await request.get_json()
        if req_json:
            id = req_json.get("id", str(uuid.uuid4()))
            doc_ref = db.collection(SUMMARY_COLLECTION).document("{}".format(id))
            req_json["created_at"] = datetime.now().isoformat()
            doc_ref.set(req_json, merge=True)
        return {
            "success": "true",
            "response": {"id": doc_ref.id, "data": req_json},
        }


def process_file(file):
    if file.filename == "":
        return {"success": "false", "message": "Empty file uploaded"}, 500
    if file and not allowed_file(file.filename):
        return {
            "success": "false",
            "message": f"File is not a supported type. Supported types are {', '.join(ALLOWED_EXTENSIONS)}",
        }, 500
    # Full report is a jsonlines file with each line representing a SARIF report
    if file.filename == SCAN_FULL_REPORT:
        for aresult in file.readlines():
            id = process_scan_result(json.loads(aresult))
            if not id:
                return {
                    "success": "false",
                    "message": "SARIF data was not processed successfully",
                }, 500
    else:
        content = file.read()
        try:
            scan_data = json.loads(content)
            id = process_scan_result(scan_data)
            if not id:
                return {
                    "success": "false",
                    "message": "Scan data was not processed successfully",
                }, 500
        except Exception:
            return {
                "success": "false",
                "message": f"Scan data was not found in json format. Filename: {file.filename}",
            }, 500
    return {"success": "true"}


def process_scan_result(scan_data):
    if not scan_data:
        return False
    id = str(uuid.uuid4())
    runs = scan_data.get("runs") if scan_data.get("runs") else [scan_data]
    for arun in runs:
        # Set the guid as the document id.
        if arun.get("automationDetails"):
            id = arun.get("automationDetails", {}).get("guid", str(uuid.uuid4()))
            arun["result_type"] = "sarif"
        # Bring version control metadata to the root to enable filtering
        if arun.get("versionControlProvenance"):
            vcs_info = arun.get("versionControlProvenance")[0]
            arun["repositoryUri"] = vcs_info.get("repositoryUri")
            arun["branch"] = vcs_info.get("branch")
            arun["revisionId"] = vcs_info.get("revisionId")
        arun["created_at"] = datetime.now().isoformat()
        doc_ref = db.collection(SCANS_COLLECTION).document("{}".format(id))
        doc_ref.set(arun, merge=True)
    return True


@app.route("/scans", methods=["GET", "POST", "DELETE"])
async def handle_scans():
    if request.method in ("GET", "DELETE"):
        args = request.args
        if not args:
            return "Not Found", 404
        db_ref = db.collection(SCANS_COLLECTION)
        id = request.args.get("id")
        repository_uri = request.args.get("repositoryUri")
        branch = request.args.get("branch")
        revision_id = request.args.get("revisionId")
        if id:
            doc_ref = db_ref.document(id)
            doc = doc_ref.get()
            if doc.exists:
                if request.method == "DELETE":
                    doc_ref.delete()
                    return {"success": "true"}
                return {
                    "success": "true",
                    "response": {"id": doc.id, "data": doc.to_dict()},
                }
        elif repository_uri:
            db_ref = db_ref.where("repositoryUri", "==", repository_uri)
            if branch:
                db_ref = db_ref.where("branch", "==", branch)
            if revision_id:
                db_ref = db_ref.where("revisionId", "==", revision_id)
            if request.method == "DELETE":
                all_docs = db_ref.stream()
            else:
                all_docs = db_ref.order_by(
                    "created_at", direction=firestore.Query.DESCENDING
                ).stream()
            docs_dict = {}
            for doc in all_docs:
                if request.method == "DELETE":
                    doc.reference.delete()
                docs_dict[doc.id] = doc.to_dict()
            if docs_dict:
                if request.method == "DELETE":
                    return {"success": "true"}
                return {"success": "true", "response": docs_dict}
        return "Not Found", 404
    if request.method == "POST":
        files = await request.files
        # check if the post request has the file part
        if "file" in files:
            file = files["file"]
            return process_file(file)
        req_json = await request.get_json()
        if req_json:
            return process_scan_result(req_json)
        return {"success": "false"}, 500


if __name__ == "__main__":
    config = Config.from_mapping(bind=[f"0.0.0.0:{int(os.environ.get('PORT', 8080))}"])
    asyncio.run(serve(app, config))
