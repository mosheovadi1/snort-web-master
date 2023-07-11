import copy
import os
import csv
import time
from io import StringIO
from django.contrib import messages
import re
import json

from import_export.admin import ImportExportModelAdmin
from django import forms

import pcaps.models
from .models import SnortRule, SnortRuleViewArray, save_rule_to_s3, delete_rule_from_s3
from .snort_templates import types_list
from .parser import Parser
from django.utils.encoding import smart_str
from django.http.response import HttpResponse, HttpResponseRedirect
from django.utils.html import mark_safe
from django.db import transaction
import suricataparser
from snort.views import build_keyword_dict, build_rule_parse, validate_pcap_snort
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions
from settings.models import Setting, attackGroup, keyword
from django.shortcuts import render
from advanced_filters.admin import AdminAdvancedFiltersMixin
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from datetime import datetime
from django.core.serializers import serialize

class StoreAdminForm(forms.ModelForm):
    ## add an extra field:
    upfile = forms.FileField()

    class Meta:
        model = SnortRule
        fields = "__all__"

    def clean(self):
        cleaned_data = super(StoreAdminForm, self).clean()

        if "upfile" in self.changed_data:
            ### file validation on file type etc here ..
            ## file is valid:
            ## next lines deal with the InMemoryUploadedFile Type
            path = settings.MEDIA_ROOT.joinpath("___tmp___")
            tmp = default_storage.save(path, ContentFile(cleaned_data["upfile"].read()))

            ## ...


BASE_FIELDS = [
    "id", "active", "is_template", "deleted", "admin_locked", 'name', "document", "treatment", "description",
    "extra", "user"]
FILTER_FIELDS = ("active", "is_template", "deleted", "admin_locked")
ADVANCE_FILTER_FIELDS = tuple(i for i in BASE_FIELDS + ["content", ("pcap_sanity_check__name", "pcap_sanity_check_name"), ("pcap_legal_check__name", "pcap_legal_check_name"),("group_name", "group_name")])
FIELDS = [
    "id", "snort_builder", "active", "is_template", "deleted", "admin_locked",'name', "document", "treatment",  "description",
    "extra", "user", 'pcap_sanity_check', "pcap_legal_check"]
SEARCH_FIELDS = tuple(i for i in BASE_FIELDS + ["content", "pcap_sanity_check__name", "pcap_legal_check__name", "group__name"])
BASE_BUILDER_KEY = ("action", "protocol", "srcipallow", "srcip", "srcportallow", "srcport", "direction", "dstipallow",
                    "dstportallow", "dstport")

INPUT_TYPE = ("srcip" , "srcport", "dstip", "dstport")
from django.core.cache import cache
# todo: upload unmanaged rule file

class SnortRuleAdminForm(forms.ModelForm):
    def clean_user(self):
        return getattr(self.current_user, self.current_user.USERNAME_FIELD)

    def clean_date(self):
        return self.cleaned_data["date"]

    def clean_type(self):
        if not dict(types_list).get(self.cleaned_data.get("type")):
            raise forms.ValidationError("cant find type, did you forgot it? or forgot to add type to db", code=404)
        return self.cleaned_data.get("type")

    def clean_content(self):
        try:
            parser = Parser(self.data["content"])
            parser.parse_header()
            options = parser.parse_options()
            for option in options:
                try:
                    if options[option][1] != [""] and options[option][0] != "tag":
                        break
                except:
                    pass
            else:
                raise forms.ValidationError("no content; please add at least one keyword, tag does not count as one.")
            if os.name != "nt":
                cur_rule = SnortRule()
                cur_rule.content = self.data.get("content")
                cur_rule.location = self.data.get("location")
                cur_rule.group = self.instance.group
                cur_rule.id = self.data.get("id")
                cur_rule.treatment = self.data.get("treatment")
                cur_rule.name = self.data.get("name")
                cur_rule.type = self.data.get("type")
                cur_rule.user = getattr(self.current_user, self.current_user.USERNAME_FIELD)
                cur_rule.document = self.data.get("document")
                pacps = [pcaps.models.Pcap(pcap_file="pacp_repo/http.cap")]
                validate_pcap_snort(pacps, cur_rule)
        except Exception as e:
            raise forms.ValidationError(e)

        return self.data["content"]

    def clean_location(self):
        try:
            if os.path.dirname(self.cleaned_data["location"]) != "":
                os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            with open(self.cleaned_data["location"], "w") as rule_file:
                rule_file.write(self.cleaned_data["content"])
        except Exception as e:
            forms.ValidationError(e)
        return self.cleaned_data["location"]

    def clean_is_template(self):
        if self.cleaned_data.get("is_template"):
            self.cleaned_data["active"] = False
        return self.cleaned_data.get("is_template")

    def clean_pcap_sanity_check(self):
        # return self.cleaned_data.get("pcap_validation")
        if not self.cleaned_data.get("pcap_sanity_check"):
            if Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "False":
                return self.cleaned_data["pcap_sanity_check"]
            elif Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "True":
                raise forms.ValidationError(
                    f"no pcap provided fof sanity check, plase add pcap or edit setting(FORCE_SANITY_CHECK)")
            else:
                raise forms.ValidationError(
                    f"bad configuration setting (FORCE_SANITY_CHECK), pleas edit setting(FORCE_SANITY_CHECK) must be True or False")
        cur_rule = SnortRule()
        cur_rule.content = self.data.get("content")
        cur_rule.location = self.data.get("location")
        cur_rule.group = self.instance.group
        cur_rule.id = self.data.get("id")
        cur_rule.treatment = self.data.get("treatment")
        cur_rule.name = self.data.get("name")
        cur_rule.type = self.data.get("type")
        cur_rule.user = getattr(self.current_user, self.current_user.USERNAME_FIELD)
        cur_rule.document = self.data.get("document")
        min_allowed = 0
        max_allowed = 0
        try:
            max_allowed = int(Setting.objects.get(**{"name": "MAX_SANITY_MATCH_ALLOWED"}).value)
        except:
            forms.ValidationError(str(Setting.objects.get(**{"name": "MAX_SANITY_MATCH_ALLOWED"})) + " for MAX_SANITY_MATCH_ALLOWED is not a valid int")
            return
        try:
            min_allowed = int(Setting.objects.get(**{"name": "MIN_SANITY_MATCH_ALLOWED"}).value)
        except:
            forms.ValidationError(
                    str(Setting.objects.get(**{"name": "MIN_SANITY_MATCH_ALLOWED"})) + " for MIN_SANITY_MATCH_ALLOWED is not a valid int")
            return
        count = validate_pcap_snort(self.cleaned_data.get("pcap_sanity_check"), cur_rule)
        print(f"clean_pcap_sanity_check: {min_allowed} <= int({count}) <= {max_allowed}")
        if min_allowed <= count <= max_allowed:
            self.cleaned_data["admin_locked"] = False
            self.instance.admin_locked = False
            self.instance.save()
            return self.cleaned_data["pcap_sanity_check"]
        elif Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "True":
            self.cleaned_data["admin_locked"] = True
            self.instance.admin_locked = True
            self.instance.save()
            if self.cleaned_data["active"] == True:
                if not self.current_user.is_staff and not self.current_user.is_superuser:
                    raise forms.ValidationError(
                        f"rule is admin locked due to high number of validations {count} > {max_allowed}, please contact admin or fix rule\n all changed of an admin locked rull must be approved by admin")

        return self.cleaned_data["pcap_sanity_check"]

    # only admin can activate admin locked rule
    def clean_pcap_legal_check(self):
        # return self.cleaned_data.get("pcap_validation")

        if not self.cleaned_data.get("pcap_legal_check"):
            if Setting.objects.get(**{"name": "FORCE_LEGAL_CHECK"}).value == "False":
                return self.cleaned_data["pcap_legal_check"]
            elif Setting.objects.get(**{"name": "FORCE_LEGAL_CHECK"}).value == "True":
                raise forms.ValidationError(
                    f"no pcap provided fof sanity check, plase add pcap or edit setting(FORCE_LEGAL_CHECK)")
            else:
                raise forms.ValidationError(
                    f"bad configuration setting (FORCE_LEGAL_CHECK), pleas edit setting(FORCE_LEGAL_CHECK) must be True or False")

        cur_rule = SnortRule()
        cur_rule.content = self.data.get("content")
        cur_rule.location = self.data.get("location")
        cur_rule.id = self.data.get("id")
        cur_rule.treatment = self.data.get("treatment")
        cur_rule.name = self.data.get("name")
        cur_rule.type = self.data.get("type")
        cur_rule.user = getattr(self.current_user, self.current_user.USERNAME_FIELD)
        cur_rule.document = self.data.get("document")
        try:
            max_allowed = int(Setting.objects.get(**{"name": "MAX_LEGAL_MATCH_ALLOWED"}).value)
        except:
            forms.ValidationError(str(Setting.objects.get(**{"name": "MAX_SANITY_MATCH_ALLOWED"})) + " for MAX_SANITY_MATCH_ALLOWED is not a valid int")
            return
        try:
            min_allowed = int(Setting.objects.get(**{"name": "MIN_LEGAL_MATCH_ALLOWED"}).value)
        except:
            forms.ValidationError(
                    str(Setting.objects.get(**{"name": "MIN_SANITY_MATCH_ALLOWED"})) + " for MIN_SANITY_MATCH_ALLOWED is not a valid int")
            return
        count = validate_pcap_snort(self.cleaned_data.get("pcap_legal_check"), cur_rule)
        print(f"clean_pcap_legal_check: {min_allowed} <= int({count}) <= {max_allowed}")
        if min_allowed <= int(count) <= max_allowed:
            self.cleaned_data["admin_locked"] = False
            self.instance.admin_locked = False
            self.instance.save()
        else:
            self.cleaned_data["admin_locked"] = True
            self.instance.admin_locked = True
            self.instance.save()
            if self.cleaned_data["active"] == True:
                if not self.current_user.is_staff and not self.current_user.is_superuser:
                    raise forms.ValidationError(
                        f"rule is admin locked due to high number of validations {count} > {max_allowed}, please contact admin or fix rule\n all changed of an admin locked rull must be approved by admin")

        return self.cleaned_data["pcap_legal_check"]

    def clean_active(self):
        if self.instance.active:
            return self.cleaned_data["active"]
        locked = False
        if self.cleaned_data.get("admin_locked") is None:
            locked = self.instance.admin_locked
        else:
            locked = self.cleaned_data.get("admin_locked")
        if self.cleaned_data["active"] and locked:
            if not self.current_user.is_staff and not self.current_user.is_superuser:
                raise forms.ValidationError(
                    f"rule is admin locked, please contact admin", code=403)
        return self.cleaned_data["active"]

    @transaction.atomic
    def clean(self):
        current_data = {}
        for info, info_path in {"group": "group.name", "name": "name", "sigid": "id", "treatment": "treatment", "description":"description", "document":"document"}.items():
            main = info_path.split(".")[0]
            current_data[info] = self.cleaned_data.get(main, self.data.get(main, getattr(self.instance, main)))
            for keypath in info_path.split(".")[1:]:
                if current_data[info]:
                    current_data[info] = getattr(current_data[info], keypath)
                else:
                    current_data[info] = ""

        if self.cleaned_data.get("content"):
            content = self.cleaned_data.get("content")
            content = content[:-1] + f'msg:"{current_data["group"]}" "{current_data["name"]}"; sid:{current_data["sigid"]}; ' \
                                     f'metadata: employee "{self.clean_user()}", group "{current_data["group"]}", ' \
                                     f'name "{current_data["name"]}",treatment "{current_data["treatment"]}", keywords "None", ' \
                                     f'date "{datetime.now().strftime("%d-%m-%Y %H:%M:%S")}", document "{current_data["document"]}",' \
                                     f'description "{current_data["description"]}";)'

        elif self.data.get("content"):
            content = self.data.get("content")
            content = content[:-1] + f'msg:"{current_data["group"]}" "{current_data["name"]}"; sid:{current_data["sigid"]}; ' \
                                     f'metadata: employee "{self.clean_user()}", group "{current_data["group"]}", ' \
                                     f'name "{current_data["name"]}",treatment "{current_data["treatment"]}", keywords "None", ' \
                                     f'date "{datetime.now().strftime("%d-%m-%Y %H:%M:%S")}", document "{current_data["document"]}",' \
                                     f'description "{current_data["description"]}";)'
        else:
            content = self.instance.content
        try:
            self.cleaned_data["user"] = self.instance.user = self.clean_user()
            regex = r"employee '\w+',"
            subst = rf"employee '{self.cleaned_data['user']}',"
            content = re.sub(regex, subst, content, 0, re.MULTILINE)
            if "user" not in self.changed_data:
                self.changed_data.append("user")
        except Exception as e:
            self.add_error("user", e)
        try:
            self.clean_content()
            if not self.current_user.is_superuser:
                res = build_rule_parse("/build_rule_parse/", self.data["content"])
                if json.loads(res.content).get("unparsed_data"):
                    raise Exception("unparsed data exists, non admin cannot add unparsed data!")
        except Exception as e:
            if not self.errors:
                self.add_error(None, e)


        self.instance.deleted = False
        if not self.instance.pk and not self.errors:
            self.instance.save()
            # set sid in content for the new rule
            if "sid:None;" in content:
                self.cleaned_data["content"] = content.replace("sid:None;", f"sid:{self.instance.pk};")
                if "content" not in self.changed_data:
                    self.changed_data.append("content")
        else:
            self.cleaned_data["content"] = content
        self.instance.content = self.cleaned_data["content"]
        if not self.errors:
            SnortRuleViewArray.objects.filter(snortId=self.instance.id).delete()
            cache.set(self.instance.id, content)
        else:
            cache.set(self.instance.id, content)
            return
        if self.cleaned_data.get("active"):
            save_rule_to_s3(self.instance.id, self.instance.content)
            pass
            # todo: save to s3
        else:
            delete_rule_from_s3(self.instance.id)
            # todo: make sure it is not on prod


@admin.register(SnortRule)
class SnortRuleAdmin(DjangoObjectActions, AdminAdvancedFiltersMixin, ImportExportModelAdmin, admin.ModelAdmin):
    list_filter = FILTER_FIELDS  # simple list filters

    # specify which fields can be selected in the advanced filter
    # creation form
    advanced_filter_fields = ADVANCE_FILTER_FIELDS
    change_actions = ('clone_rule',)
    # changelist_actions = ('load_template',)

    FIELDS_GROUP = FIELDS
    rule_validation_fields = ("pcap_sanity_check", "pcap_legal_check")
    for field in rule_validation_fields:
        if field in FIELDS_GROUP:
            FIELDS_GROUP.remove(field)
    fieldsets = (
        (None, {"fields": FIELDS_GROUP}),
        ("attackers", {"fields": ("group",)}),
        ("Rule validation", {"fields": rule_validation_fields}),
    )
    filter_horizontal = ('pcap_sanity_check', "pcap_legal_check")
    list_display_links = ("id", "user", "name", "content", "description")
    list_display = ("id", "user", "active", "name", "group", "description", "content", "date", "is_template", "deleted")
    search_fields = SEARCH_FIELDS
    form = SnortRuleAdminForm
    actions = ['make_published', "make_delete", "make_clone"]

    def export_action(self, request):
        return self.export_data(SnortRule.objects.all())

    @transaction.atomic
    def import_action(self, request):
        errors = False
        if request.method == 'POST':
            snort_rules_to_save = []
            snort_rules_options_to_save = {}
            try:
                csv_file = request.FILES['myfile']
                if not csv_file.name.endswith('.csv'):
                    messages.error(request, 'File is not CSV type')
                    return HttpResponseRedirect("/admin/snort/snortrule/import/")
                # if file is too large, return
                if csv_file.multiple_chunks():
                    messages.error(request, "Uploaded file is too big (%.2f MB)." % (csv_file.size / (1000 * 1000),))
                    return HttpResponseRedirect("/admin/snort/snortrule/import/")

                file_data = csv.DictReader(StringIO(csv_file.read().decode("utf-8")))
                # loop over the lines and save them in db. If error , store as string and then display
                for item in file_data:
                    snort_rule = SnortRule()
                    snort_rule.active = item["Active"]
                    snort_rule.deleted = item["Deleted"]
                    snort_rule.user = getattr(request.user, request.user.USERNAME_FIELD)
                    snort_rule.description = item["Description"]
                    snort_rule.extra = item["Extra"]
                    if item.get("Group"):
                        snort_rule.group = attackGroup.objects.get(name=item["Group"])
                    snort_rule.name = item["Name"]
                    if item.get("Id") and item.get("Update") and request.user.is_superuser:
                        snort_rule.id = item["Id"]
                    else:
                        temp_id = str(time.time())
                        snort_rule.id = "temp " + temp_id
                    snort_rule.content = item["Rule"]

                    try:
                        resppnse = {"data": []}
                        try:
                            rule_parsed = Parser(item["Rule"], set([op.name for op in keyword.objects.filter(stage="service", available=True)]))
                        except:
                            raise Exception("bad rule format")
                        build_keyword_dict(resppnse, rule_parsed)
                        for op in rule_parsed.options:
                            if rule_parsed.options[op][0] == "msg":
                                if snort_rule.group:
                                    rule_parsed.options[op] = "msg", [snort_rule.group.name + " "]
                                else:
                                    rule_parsed.options[op] = "msg", [""]
                                if snort_rule.name:
                                    rule_parsed.options[op][1][0] += snort_rule.name
                                continue
                            if rule_parsed.options[op][0] == "sid":
                                rule_parsed.options[op] = "sid", [snort_rule.id]
                                continue
                            if rule_parsed.options[op][0] == "metadata":
                                new_value = []
                                user_applyed = False
                                for item_metadata in rule_parsed.options[op][1]:
                                    if item_metadata.strip("'").strip().startswith("group "):
                                        if snort_rule.group:
                                            new_value.append(f"group {snort_rule.group.name}")
                                            continue
                                    if item_metadata.strip("'").strip().startswith("name "):
                                        new_value.append(f"name {snort_rule.name}")
                                        continue
                                    if item_metadata.strip("'").strip().startswith("description "):
                                        new_value.append(f"description {snort_rule.description}")
                                        continue
                                    if item_metadata.strip("'").strip().startswith("employee "):
                                        new_value.append(f"employee {snort_rule.user}")
                                        user_applyed = False
                                        continue
                                    if item_metadata.strip("'").strip().startswith("document "):
                                        snort_rule.treatment = item_metadata.strip("'").strip().replace("document ", "")
                                    if item_metadata.strip("'").strip().startswith("treatment "):
                                        snort_rule.document = item_metadata.strip("'").strip().replace("document ", "")
                                    new_value.append(item_metadata)
                                if not user_applyed:
                                    new_value.append(f"employee {snort_rule.user}")
                                rule_parsed.options[op] = "metadata", new_value
                                continue
                        snort_rule.content = rule_parsed
                        snort_rules_to_save.append(snort_rule)
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                        errors = True
                        messages.error(request, f"Unable to load rule {item['Name']}. {repr(e)}")
                        pass

            except Exception as e:
                errors = True
                messages.error(request, "Unable to upload file. " + repr(e))
            if not errors:
                for rule in snort_rules_to_save:
                    rule_id = rule.id
                    if rule_id.startswith("temp "):
                        rule.id = None
                        rule_parsed = rule.content
                        for op in rule_parsed.options:
                            if op.name == "sid":
                                op.value = 0
                                break
                        rule.content = ""
                        rule.save()
                        for op in rule_parsed.options:
                            if op.name == "sid":
                                op.value = rule.id
                                break
                    rule.content = rule_parsed.rule
                    rule.save()
                    if rule.active:
                        save_rule_to_s3(rule.id, rule.content)
                    else:
                        delete_rule_from_s3(rule.id)
                return HttpResponseRedirect("/admin/snort/snortrule/")
            return HttpResponseRedirect("/admin/snort/snortrule/import/")

        return render(request, 'html/import.html')

    @admin.action(description='Mark selected snort rule as deleted')
    def make_delete(self, request, queryset):
        for rule in queryset:
            rule.delete()
        return HttpResponseRedirect("/admin/snort/snortrule/")

    @admin.action(description='clone selected rule (1 only)')
    def make_clone(self, request, queryset):
        if len(queryset) > 1:
            messages.error(request, "cannot clone more than 1 rule at a time")
            return
        if len(queryset) == 0:
            messages.error(request, "need exactly 1 rule to clone")
            return
        for rule in queryset:
            self.request = request
            request.session["instance"] = serialize('json', [rule])
        request.path = "/admin/snort/snortrule/add/"
        request.path_info = "/admin/snort/snortrule/add/"
        request.method = "GET"
        return self.changeform_view(request, object_id=None)

    @admin.action(description='export selected snort to csv')
    def make_published(self, request, queryset):
        return self.export_data(queryset)

    def export_data(self, queryset):
        response = HttpResponse(
            content_type='application/force-download')  # mimetype is replaced by content_type for django 1.7
        response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(f"SnortRule-{datetime.now()}.csv")
        str_content = "Active,Date,Deleted,Description,Extra,Group,Name,Id,User,Rule\n"
        for snort_item in queryset:
            content = snort_item.content.replace('"', "'")
            my_list = [snort_item.active, snort_item.date, snort_item.deleted, snort_item.description, snort_item.extra,
                       snort_item.group, snort_item.name, snort_item.pk, snort_item.user, content]
            for item in my_list:
                if isinstance(item, bool):
                    str_content += str(item) + ","
                    continue
                if not item:
                    str_content += ','
                    continue
                str_content += '"' + str(item) + '",'
                continue
            str_content = str_content[:-1] + "\n"
        response.content = smart_str(str_content)
        # It's usually a good idea to set the 'Content-Length' header too.
        # You can also set any other required headers: Cache-Control, etc.
        return response

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def snort_builder(self, obj):
        # set_rule = cache.get(obj.id)
        # if not set_rule:
        #     set_rule = SnortRuleViewArray.objects.filter(snortId=obj.id)
        #     cache.set(obj.id, set_rule)
        # else:
        #     cache.set(obj.id, [])
        context = {}
        # todo handle caching of rule
        # context["build_items"] = set_rule
        # context["actions"] = keyword.objects.filter(stage="action", available="True")
        # context["protocols"] = keyword.objects.filter(stage="protocol", available="True")

        tmp_context = copy.deepcopy(self.request.session.get("cloned_rule", {}))
        self.request.session["cloned_rule"] = {}
        tmp_context.update(context)

        snort_buider_section = render(self.request, "html/snortBuilder.html", tmp_context).content.decode("utf-8")
        full_rule_js = render(self.request, "html/full_rule.html")
        return mark_safe(full_rule_js.content.decode("utf-8") + snort_buider_section)

    def get_form(self, request, *args, **kwargs):
        form = super(SnortRuleAdmin, self).get_form(request, **kwargs)
        form.current_user = request.user
        self.request = request
        form.base_fields["pcap_sanity_check"].help_text = "Hold down “Control” to select more than one."
        form.base_fields["pcap_legal_check"].help_text = "Hold down “Control” to select more than one."
        atkgroup = form.base_fields["group"]
        atkgroup.widget.can_add_related = Setting.objects.get_or_create(**{"name": "atkgroup_can_add_related"})[0].value == "True"
        atkgroup.widget.can_change_related = Setting.objects.get_or_create(**{"name": "atkgroup_can_change_related"})[0].value == "True"
        atkgroup.widget.can_delete_related = Setting.objects.get_or_create(**{"name": "atkgroup_can_delete_related"})[0].value == "True"
        atkgroup.widget.can_view_related = Setting.objects.get_or_create(**{"name": "atkgroup_can_view_related"})[0].value == "True"
        a = Setting.objects.get_or_create(**{"name": "MAX_SANITY_MATCH_ALLOWED"},defaults={"value": 1000})
        if a[1]:
            a = Setting.objects.get_or_create(**{"name": "MIN_SANITY_MATCH_ALLOWED"}, defaults={"value": 0})
            a = Setting.objects.get_or_create(**{"name": "MAX_LEGAL_MATCH_ALLOWED"}, defaults={"value": 0})
            a = Setting.objects.get_or_create(**{"name": "MIN_LEGAL_MATCH_ALLOWED"}, defaults={"value": 0})
        return form

    @transaction.atomic
    def clone_rule(self, request, obj: SnortRule):
        # todo: clone rule does not work from main page
        # todo: clone rule does not work from rule page
        request.session["instance"] = serialize('json', [obj])
        return HttpResponseRedirect(f"/snort/snortrule/add/")

    clone_rule.label = "clone_rule"  # optional

    def get_readonly_fields(self, request, obj=None):
        if obj and (obj.is_template or obj.admin_locked):
            read_only_fields = (
            "id", "snort_builder", "active", "user", "admin_locked", "deleted", "rule_validation_section",)
        else:
            read_only_fields = ("id", "snort_builder", "user", "admin_locked", "deleted", "rule_validation_section")

        return read_only_fields

    # readonly_fields = ("id", "user", "admin_locked", "full_rule", "snort_builder", "deleted")
    clone_rule.short_description = "clone rule to a new rule"  # optional