# Generated by Django 4.1.2 on 2022-11-07 06:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('snort', '0004_alter_snortrule_pcap_validation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='snortrule',
            name='template',
            field=models.TextField(choices=[('abcdefghijklmnop', 'type a')], max_length=30),
        ),
    ]
