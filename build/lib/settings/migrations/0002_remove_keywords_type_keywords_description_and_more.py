# Generated by Django 4.1.2 on 2022-12-26 06:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('settings', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='keywords',
            name='type',
        ),
        migrations.AddField(
            model_name='keywords',
            name='description',
            field=models.CharField(blank=True, help_text='Value of site-wide variable that scripts can reference', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='keywords',
            name='negation',
            field=models.CharField(blank=True, help_text='Value of site-wide variable that scripts can reference', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='keywords',
            name='options',
            field=models.CharField(blank=True, help_text='Value of site-wide variable that scripts can reference', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='keywords',
            name='stage',
            field=models.CharField(blank=True, help_text='Value of site-wide variable that scripts can reference', max_length=100, null=True),
        ),
    ]
