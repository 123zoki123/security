# Available online:

You can  visit https://boiling-badlands-45501.herokuapp.com/api/v1/ for hosted version.

It's hosted on Heroku, american server, might take a while to load. :(

# How to run this code locally:

First you would need to clone the repository. Create new folder, navigate inside it and:

`git clone git@github.com:123zoki123/security.git`


Might need to update the file permissions locally:

`$ chmod +x security/entrypoint.sh`

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

You should see the data populated there, and on the remaining links.

To run the tests:

`docker-compose exec security pytest`

# Thoughts behind building this app

I could've easily just read the json files and return the data in the response. That would be the easiest solution
however I took a different approach.
Reasons for this approach are personal with the idea of reminding myself on how Django and DRF work and
this task served well for that.

## Models
==========

I've decided to use Postgresql database for no reasons. However I do use fields that are specific for Postgres such as
ArrayField, JSONField. These fields have not impacted the decision for using Postgresql at all, the logic could've been done without them too.

### Asset and User
==================

Seeing that data that comes in the json files I can spot that User and Asset are standalone models so they can be created without any relations to other tables to begin with.

### Scan
========

The scan data has got requested_by field which indicates that a foreign key should be used here with the idea of
one user being able to request multiple scans.

The status data contains only "completed" and "failed" so that's a good indicator for enum. Could've been done differently
with using newest django features such as `models.TextChoices`. No reasons behind this, I work with enums therefore chose
the enum module, `enum.Enum`, approach.

The assets_scanned data indicates to use ManyToMany relation because almost the same assets are repeating in
both Scan objects. So a Scan can have many assets and seen from here and asset can be scanned many times.

For the scanners I decided to go with array field for easier display of values. Since we are not doing any search
this is fine, however ideal approach would've been to create separate model, and link it as Many to Many because they
are repeating for different scans.

For severity_counts I decided to go with JSONField and this is fine approach to deal with this. There might be 
better approach for this with creating another table putting a many to many relation again however would need more
input before such decision.

Rest of the fields are self explanatory and I think not worth the discussion.

### Vulnerability
=================

For severity we have the same values repeating on the models therefore it's a good candidate for enum, as I 
have implemented.

These fields I think are basic and self explanatory when you look at the model.
name
cvss_base_score

These are TextFields since they can accept more than 255 characters.
description
solution

References look like large string containing URLs separated by blank space or just nulls which made me think about storing them as URLFields inside an ArrayField. Probably could've been done differently with just storing the whole string inside
and displaying it, however this implementation gives better display of information inside it and allows you follow the URL
and navigate to the resource.

from_scan is a good indicator to use ForeignKey and that's about it I believe, one scan can have many vulnerabilities.

assets are same as for scan
(The affected_assets data indicates to use ManyToMany relation because almost the same assets are repeating in
all Vulnerability objects)

## Serializers
==============

Decided to use HyperlinkedModelSerializer, on Asset and User models, which is ModelSerializer just to add navigation from the Vulnerabilities and Scans to these objects, with adding an url key in the responses.

ScanSerializer, VulnerabilitySerializer are using plain ModelSerializers with overriding the model names to the ones
that are coming from the json files. Also inheriting the `serializers.ChoiceField` and overriding `to_representation` 
because I want to have the enum value instead of the enum name as output from the serializer.

## Views
========

Decided to go with ReadOnlyModelViewSet because it gives list and detail view of a model which are the requiements for
this project. They only require queryset and serializer and that's all, the magic happens in the background.
Once again could've taken different approach and use more basic code with me implementing all the code from
request to response.

## Docker
=========

The dockerfile is quite basic with having an entrypoint command that allows to wait for the database service since this
service (security) depends on it being up and healthy.

In docker-compose just adding 2 services, security and security-db, the security service runs the python app 
whenever we run docker-compose up. 

Notes about models:
- Not doing any search in the array fields therefor there won't be any performance issues, known for ArrayField
for the sake of the project keeping it simple using these fields
- They are from postgres contrib however I do not chose postgres for these fields
- Another, and I think much better solution is to use foreign keys to other tables that contain the data and do calculations on those
- Also not extending the django user model just because there won't be any authentication on the api endpoint


Project Requirements, as they were.

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
