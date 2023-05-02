from django.db import models
from settings.models import attackGroup
from .snort_templates import types_list

class SnortRule(models.Model):
    id = models.AutoField(primary_key=True)
    group = models.ForeignKey(attackGroup, blank=True, null=True, on_delete=models.SET_NULL)
    active = models.BooleanField(default=False)
    admin_locked = models.BooleanField(default=False)
    user = models.CharField(max_length=100, blank=True, default=0)
    name = models.CharField(max_length=100)
    type = models.TextField(max_length=30, choices=types_list)
    content = models.TextField(max_length=2048)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256, blank=True)
    location = models.CharField(max_length=256)
    document = models.CharField(max_length=12, blank=True)
    treatment = models.CharField(max_length=12, blank=True)
    date = models.DateTimeField(auto_now=True)
    is_template = models.BooleanField(default=False)
    pcap_sanity_check = models.ManyToManyField("pcaps.Pcap", related_name='pcap_sanity_check', blank=True)
    pcap_legal_check = models.ManyToManyField("pcaps.white_Pcap", related_name='pcap_legal_check', blank=True)
    objects = models.Manager()
    deleted = models.BooleanField(default=False)
    tag = models.BooleanField(default=True, help_text="add 'tag:session,10,packets' to rule")

    def delete(self):
        self.active = False
        self.deleted = True
        self.save()
    class Meta:
        ordering = ("name", "type", "date")


class SnortRuleViewArray(models.Model):
    id = models.AutoField(primary_key=True)
    snortId = models.ForeignKey('snort.SnortRule', blank=True, null=True, on_delete=models.SET_NULL)
    typeOfItem = models.CharField(max_length=20, blank=True)
    locationX = models.IntegerField()
    locationY = models.IntegerField()
    value = models.CharField(max_length=256, blank=True)
    htmlId = models.CharField(max_length=50, blank=True)

def delete_rule_from_s3(rule_id):
    # todo: implement
    # check if exists
    # delete
    pass
def save_rule_to_s3(rule_id, rule_content):
    # upsert rule
    pass