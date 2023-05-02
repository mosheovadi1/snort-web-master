from django.db import models

# Create your models here.


class Pcap(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256,blank=True)
    pcap_file = models.FileField(upload_to="pacp_repo/", null=True)
    date = models.DateTimeField(auto_now=True)
    rule_to_validate = models.ForeignKey('snort.SnortRule', blank=True, null=True, on_delete=models.SET_NULL)
    objects = models.Manager()

    def __str__(self):
        return self.name

class white_Pcap(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256,blank=True)
    pcap_file = models.FileField(upload_to="pacp_repo/", null=True)
    date = models.DateTimeField(auto_now=True)
    rule_to_validate = models.ForeignKey('snort.SnortRule', blank=True, null=True, on_delete=models.SET_NULL)
    objects = models.Manager()

    def __str__(self):
        return self.name

