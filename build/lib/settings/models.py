from django.db import models

# Create your models here.
class Setting(models.Model):
    """
    Model for site-wide settings.
    """
    name = models.CharField(max_length=200, help_text="Name of site-wide variable")
    value = models.CharField(null=True, blank=True, max_length=100, help_text="Value of site-wide variable that scripts can reference - must be valid JSON")

    def __unicode__(self):
        return self.name


class attackGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    objects = models.Manager()

    def __str__(self):
        return self.name

# Create your models here.
class keyword(models.Model):
    """
    Model for site-wide settings.
    """
    name = models.CharField(max_length=200, help_text="keyword name")
    stage = models.CharField(null=True, blank=True, max_length=100, help_text="where will the keyword element will appeare in snort builder")
    description = models.CharField(null=True, blank=True, max_length=100, help_text="just a description")
    options = models.CharField(null=True, blank=True, max_length=100,
                                help_text="what type of field is it, does it has sub fields")
    available = models.BooleanField(default=False,
                                help_text="is it available in snort builder")
    def __unicode__(self):
        return self.name