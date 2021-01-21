import json
from typing import List
from core.models import Asset, User, Vulnerability, Scan

"""
This module will contain scripts that will extract the data from the json files and store in the database
as the requested models
"""

ASSETS = "assets.json"
SCANS = "scans.json"
USERS = "users.json"
VUlNERABILITIES = "vulnerabilities.json"


def read_json_file(file_name: str) -> List[dict]:
    with open(file_name) as json_file:
        data = json.loads(json_file)
        return data


def create_users(json_data: List[dict]) -> None:
    try:
        for user in read_json_file(USERS):
            User.create(**user)
    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_vulnerabilities() -> None:
    try:
        for vuln in read_json_file(VUlNERABILITIES):
            vuln_obj = Vulnerability(
                id=vuln.get("id"),
                from_scan=vuln.get("from_scan"),
                severity=vuln.get("severity"),
                name=vuln.get("name"),
                description=vuln.get("description"),
                solution=vuln.get("solution"),
                cvss_base_score=float(vuln.get("cvss_base_score")),
            )
            refs = []
            for ref in vuln.get("references").split(""):
                ref.append(ref)
            vuln_obj.references = refs
            vuln_obj.scans_id = vuln.get("from_scan")

            for a in vuln.get("affected_assets"):
                vuln_obj.affected_assets.add(a)

            vuln_obj.save()
    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_scans() -> None:
    try:
        for scan in read_json_file(SCANS):
            # assets_scanned
            scan_obj = Scan(
                id=scan.get("id"),
                started_at=scan.get("started_at"),
                finished_at=scan.get("finished_at"),
                name=scan.get("name"),
                status=scan.get("status"),
            )
            scan_obj.request_by_id = scan.get("requested_by")
            scanners = []
            [scanners.append(s) for s in scan.get("scanners")]
            scan_obj.scanners = scanners
            scan_obj.severity_counts = scan.get("severity_counts")
            for fkey in scan.get("assets_scanned"):
                scan_obj.assets_scanned.add(fkey)
            scan_obj.save()

    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_assets() -> None:
    try:
        for asset in read_json_file(ASSETS):
            asset_obj = Asset(**asset)
    except Exception as e:
        print("Something went wrong, exception: ", e)