import json
from typing import List, Any
from core.models import Asset, Severity, Status, User, Vulnerability, Scan

ASSETS = "assets.json"
SCANS = "scans.json"
USERS = "users.json"
VUlNERABILITIES = "vulnerabilities.json"


def get_values_helper(input_dict: dict, key_word_partial: str) -> Any:
    """
    Helper method that extracts the value of a key in dictionary
    the key name can be different but stands for the same value
    """
    for k in input_dict.keys():
        if k.startswith(key_word_partial):
            return input_dict.get(k)


def read_json_file(file_name: str) -> List[dict]:
    with open(file_name, "r") as json_file:
        data = json.loads(json_file.read())
        return data


def create_users() -> None:
    """
    Method that loops through users json data and
    saves them as User model in the database
    TODO: Can do multiple inserts at a time instead
    """
    try:
        for user in read_json_file(USERS):
            User.objects.create(**user)
    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_vulnerabilities() -> None:
    """
    Method that loops through vulnerability json data
    and saves the data as Vulnerability model in the database
    after doing some processing and making relations to other models
    """
    try:
        for vuln in read_json_file(VUlNERABILITIES):
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
    """
    Method that loops through scans json data
    and saves the data as Scan model in the database
    after doing some processing and making relations to other models
    """
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
            scan_obj.scanners = [s for s in scan.get("scanners")]
            scan_obj.severity_counts = scan.get("severity_counts")
            scan_obj.save()
            assets = Asset.objects.filter(pk__in=scan.get("assets_scanned"))
            for asset in assets:
                scan_obj.assets.add(asset)
            scan_obj.save()

    except Exception as e:
        print("Something went wrong, exception: ", e)


def create_assets() -> None:
    """
    Method that loops through assets json data and
    saves them as Asset model in the database
    TODO: Can do multiple inserts at a time instead
    """
    try:
        for asset in read_json_file(ASSETS):
            Asset.objects.create(**asset)
    except Exception as e:
        print("Something went wrong, exception: ", e)


def run():
    create_users()
    create_assets()
    create_scans()
    create_vulnerabilities()
