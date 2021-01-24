# Generated by Django 3.1.5 on 2021-01-24 15:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_auto_20210123_0044'),
    ]

    operations = [
        migrations.RenameField(
            model_name='vulnerability',
            old_name='affected_assets',
            new_name='assets',
        ),
        migrations.RenameField(
            model_name='vulnerability',
            old_name='scans',
            new_name='scan',
        ),
        migrations.AlterField(
            model_name='scan',
            name='requested_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='scans', to='core.user'),
        ),
    ]
