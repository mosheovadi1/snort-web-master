# Generated by Django 4.1.2 on 2023-01-08 18:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('settings', '0003_keywords_avalable'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='keywords',
            name='negation',
        ),
    ]
