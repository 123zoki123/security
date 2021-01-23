# Generated by Django 3.1.5 on 2021-01-22 22:34

import core.models
import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('name', models.CharField(max_length=255)),
                ('status', models.CharField(choices=[(core.models.Status['COMPLETED'], 'completed'), (core.models.Status['FAILED'], 'failed')], max_length=50)),
                ('scanners', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(blank=True, max_length=50, null=True), size=None)),
                ('severity_counts', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('severity', models.CharField(choices=[(core.models.Severity['INFORMATION'], 'information'), (core.models.Severity['MEDIUM'], 'medium'), (core.models.Severity['HIGH'], 'high'), (core.models.Severity['LOW'], 'low')], max_length=50)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('solution', models.TextField()),
                ('references', django.contrib.postgres.fields.ArrayField(base_field=models.URLField(blank=True, null=True), size=None)),
                ('cvss_base_score', models.DecimalField(decimal_places=1, max_digits=2)),
                ('scans', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='vulnerabilities', to='core.scan')),
            ],
        ),
        migrations.AddField(
            model_name='scan',
            name='requested_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='user', to='core.user'),
        ),
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='assets_scanned', to='core.scan')),
                ('vulnerability', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='affected_assets', to='core.vulnerability')),
            ],
        ),
    ]