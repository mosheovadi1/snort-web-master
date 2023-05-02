from django.contrib import admin
from django import forms
import os
from .models import Pcap, white_Pcap


class PcapAdminForm(forms.ModelForm):
    class Meta:
        model = Pcap
        fields = "__all__"

    def clean_pcap_file(self):
        try:
            if not verify_legal_pcap(self.cleaned_data.get("pcap_file")):
                raise Exception(f"illegal pcap file")
        except Exception as e:
            raise forms.ValidationError(f"cant validate pcap file: {e}")

        old_pcap_file = self.initial.get("pcap_file").url if hasattr(self.initial.get("pcap_file"), "url") else ""
        delete_old = False
        if os.path.exists(old_pcap_file):
            if hasattr(self.cleaned_data.get("pcap_file"), "url"):
                if self.initial.get("pcap_file").url != self.cleaned_data.get("pcap_file").url:
                    delete_old = True
            else:
                delete_old = True
        if delete_old:
            os.remove(self.initial.get("pcap_file").url)
        return self.cleaned_data.get("pcap_file")


@admin.register(white_Pcap)
class SnortRuleAdmin(admin.ModelAdmin):
    def validate(self, request, obj: white_Pcap):
        # test saved rule vs pcap
        print("validate button pushed", obj.name)
    # validate.label = "validate"  # optional
    # validate.color = "green"
    # validate.short_description = "Submit this article"  # optional

    # change_actions = ('validate', )
    # changelist_actions = ('validate',)

    list_display = ("name", "description", "pcap_file", "rule_to_validate", "date")
    search_fields = ("name", "description", "pcap_file", "rule_to_validate")
    # form = SnortRuleAdminForm


@admin.register(Pcap)
class SnortRuleAdmin(admin.ModelAdmin):
    def validate(self, request, obj: Pcap):
        # test saved rule vs pcap
        print("validate button pushed", obj.name)
    # validate.label = "validate"  # optional
    # validate.color = "green"
    # validate.short_description = "Submit this article"  # optional

    # change_actions = ('validate', )
    # changelist_actions = ('validate',)

    list_display = ("name", "description", "pcap_file", "rule_to_validate", "date")
    search_fields = ("name", "description", "pcap_file", "rule_to_validate")
    # form = SnortRuleAdminForm


def verify_legal_pcap(filename):
    import dpkt
    counter = 0

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'br')):

        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

    if not counter:
        return False
    return True
