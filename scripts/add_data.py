import json
from typing import List, Any
from core.models import Asset, Severity, Status, User, Vulnerability, Scan

"""
This module will contain scripts that will extract the data from the json files and store in the database
as the requested models
"""

ASSETS = "assets.json"
SCANS = "scans.json"
USERS = "users.json"
VUlNERABILITIES = "vulnerabilities.json"


def read_json_file(file_name: str) -> List[dict]:
    with open(file_name, "r") as json_file:
        data = json.loads(json_file.read())
        return data


def create_users() -> None:
    try:
        for user in read_json_file(USERS):
            user = User(**user)
            user.save()
    except Exception as e:
        print("Something went wrong, exception: ", e)


def get_values_helper(input_dict: dict, key_word_partial: str) -> Any:
    for k in input_dict.keys():
        if k.startswith(key_word_partial):
            return input_dict.get(k)


def create_vulnerabilities() -> None:
    try:
        for vuln in read_json_file(VUlNERABILITIES):
            print(float(vuln.get("cvss_base_score")))
            vuln_obj = Vulnerability(
                id=vuln.get("id"),
                severity=Severity.get_enum(vuln.get("severity")),
                name=vuln.get("name"),
                description=vuln.get("description"),
                solution=vuln.get("solution"),
                cvss_base_score=float(vuln.get("cvss_base_score")),
            )
            refs = []
            if ref_string := vuln.get("references"):
                for ref in ref_string.split(" "):
                    refs.append(ref)

            vuln_obj.references = refs
            vuln_obj.scans_id = vuln.get("from_scan")

            vuln_obj.save()
            assets = Asset.objects.filter(pk__in=get_values_helper(vuln, "affected"))
            for a in assets:
                vuln_obj.affected_assets.add(a)
            vuln_obj.save()

    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_scans() -> None:
    try:
        for scan in read_json_file(SCANS):
            scan_obj = Scan(
                id=scan.get("id"),
                started_at=scan.get("started_at"),
                finished_at=scan.get("finished_at"),
                name=scan.get("name"),
                status=Status.get_enum(scan.get("status")),
            )
            scan_obj.requested_by = User.objects.get(pk=scan.get("requested_by"))
            scanners = []
            [scanners.append(s) for s in scan.get("scanners")]
            scan_obj.scanners = scanners
            scan_obj.severity_counts = scan.get("severity_counts")

            assets = Asset.objects.filter(pk__in=scan.get("assets_scanned"))
            scan_obj.save()
            for asset in assets:
                print(asset)
                scan_obj.assets.add(asset)
            scan_obj.save()

    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_assets() -> None:
    try:
        for asset in read_json_file(ASSETS):
            asset_obj = Asset(**asset)
            asset_obj.save()
    except Exception as e:
        print("Something went wrong, exception: ", e)


def run():
    # create_assets()
    # create_scans()
    create_vulnerabilities()
