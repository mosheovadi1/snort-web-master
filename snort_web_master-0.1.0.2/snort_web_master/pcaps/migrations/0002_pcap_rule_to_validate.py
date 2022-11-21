# Generated by Django 4.1.2 on 2022-10-31 13:25

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('snort', '0002_alter_snortrule_options_alter_snortrule_extra_and_more'),
        ('pcaps', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='pcap',
            name='rule_to_validate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='snort.snortrule'),
        ),
    ]
