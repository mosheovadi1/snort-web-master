# Generated by Django 4.1.2 on 2022-12-19 18:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('pcaps', '0003_rename_rule_to_validate_pcap_rule_to_validate2_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='pcap',
            old_name='rule_to_validate2',
            new_name='rule_to_validate',
        ),
        migrations.RenameField(
            model_name='white_pcap',
            old_name='rule_to_validate2',
            new_name='rule_to_validate',
        ),
    ]
