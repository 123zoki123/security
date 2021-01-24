Overview
========

The attached folder contains several json files for a vulnerability scan application, we’ve included all data that you would normally get from a number of endpoints.

A vulnerability scan is an audit on a network connected device and reports on exploits that may be present. A scanner will connect to and search the device (known as an asset) looking for operating systems and software versions, from this it can determine what Common Vulnerabilities Exposures (CVE) are present on that asset. Each vulnerability found will carry a CVE Base Score – this is a number that will determine the severity of the Vulnerability on the asset at that time.

Scenario
========

In this scenario we would like you to create a Python API that is capable of returning the objects provided in the attached files in any human/machine readable format (JSON, XML, YAML, etc).

The attached files contain the following:
* **User object – users.json**

    This gives information about users registered on the system

* **Scan object – scans.json**

    This gives information about scans that have been performed

    **Additional attributes:**

    * Requested By - requested_by:

        The ID of the user that requested the scan

    * Scanners – scanners:

        Which scanners were used on this scan
    * Severity Counts – severity_counts:

        Contains information on the count of each severity found in the scan

    * Assets Scanned – assets_scanned

        A list of assets IDs that were scanned

* **Asset Object - assets.json**

    This gives information about assets that have been registered on the system

* **Vulnerability Object - vulnerabilities.json**

    This gives information about vulnerabilities that have been found during a scan and the assets they affect.

    **Additional attributes:**

    * Affected Assets - affected_assets:

        A list of asset IDs that are affected by this vulnerability

    * From Scan - from_scan:

        The ID of the scan this vulnerability was found during

What we’d like you to do
========================

How you approach this task is completely up to you. The API should respond in RPC, Restful, GraphQL or anything else you would like to use. All the data provided must be available through your API but you are welcome to add additional data if you want.

We’re not concerned if it’s not finished, how you tackle the problem is more important for us to see. – if you are able to put it somewhere we can get to – we would suggest GitHub we can discuss this in detail at your interview.

Please provide details in the README of how to run your code and your thinking whilst working on this project.


Notes about models
- Not doing any search in the array fields therefor there won't be any performance issues, known for ArrayField
- for the sake of the project keeping it simple using these fields
- They are from postgres contrib however I do not chose postgres for these fields
- Another, and I think much better solution is to use foreign keys to other tables that contain the data and do calculations on those
- Once again, using ArrayField nad JSONField just for the sake of the example, to keep it short and simple
- Also not extending the django user model just because there won't be any authentication on the api endpoint
- fully aware that there can be restrictions however it isn't specified

# How to run this app:
You can  visit https://boiling-badlands-45501.herokuapp.com/api/v1/ for hosted version.

# How to run this code locally:

First you would need to clone the repository. Create new folder, navigate inside it and:

`git clone git@github.com:123zoki123/security.git`

After that run:

`docker-compose up -d --build`

After this builds successfully navigate to your browser and open:

`http://localhost:8009/api/v1/`

The links are available for navigation however there's no data inside the db. In order to populate it you have to run
migrations first:

`docker-compose exec security python manage.py makemigrations --noinput`

After the migrations are finished then run:

`docker-compose exec security python manage.py runscript add_data`

If you go in your browser again and try:

`http://localhost:8009/api/v1/`

and try to click on any of the links, for example:

`http://localhost:8009/api/v1/vulnerabilities/`

You should see the data populated there.