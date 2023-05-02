import suricataparser
from django.http.response import HttpResponse, JsonResponse
from snort.models import SnortRule, SnortRuleViewArray
import json
import os
from django.conf import settings
# Create your views here.

def get_rule_keys(request, rule_id=None):
    rule_keywordss = SnortRuleViewArray.objects.filter(**{"snortId": rule_id})
    results = {"data": []}
    for rule_key in rule_keywordss:
        results["data"].append({"htmlId": rule_key.htmlId, "value": rule_key.value, "typeOfItem": rule_key.typeOfItem,
                        "locationX": rule_key.locationX, "locationY": rule_key.locationY})
    return JsonResponse(results)


def get_rule(request, rule_id=None):
    full_rule = SnortRule.objects.get(**{"id": rule_id}).content

    return HttpResponse(full_rule)


def build_rule_keyword_to_rule(request, full_rule=""):
    if not full_rule:
        full_rule = json.loads(request.body.decode()).get("fule_rule")
    resppnse = {"data": []}
    rule_parsed = suricataparser.parse_rule(full_rule.replace("sid:-;", ""))
    build_keyword_dict(resppnse, rule_parsed)
    return JsonResponse(resppnse)


def get_current_user_name(request):
    return JsonResponse({"user": getattr(request.user, request.user.USERNAME_FIELD)})


def build_keyword_dict(resppnse, rule_parsed):
    if not rule_parsed:
        return
    rule_keywordss = [build_keyword_item("action", rule_parsed.action),
                      build_keyword_item("protocol", rule_parsed.header.split(" ")[0]),
                      build_keyword_item("srcipallow",
                                         "!" if rule_parsed.header.split(" ")[1].startswith("!") else "-----"),
                      build_keyword_item("srcip", rule_parsed.header.split(" ")[1][1:] if rule_parsed.header.split(" ")[
                          1].startswith("!") else rule_parsed.header.split(" ")[1], item_type="input"),
                      build_keyword_item("srcportallow",
                                         "!" if rule_parsed.header.split(" ")[2].startswith("!") else "-----"),
                      build_keyword_item("srcport",
                                         rule_parsed.header.split(" ")[2][1:] if rule_parsed.header.split(" ")[
                                             2].startswith("!") else rule_parsed.header.split(" ")[2],
                                         item_type="input"),
                      build_keyword_item("direction", rule_parsed.header.split(" ")[3]),
                      build_keyword_item("dstipallow",
                                         "!" if rule_parsed.header.split(" ")[4].startswith("!") else "-----"),
                      build_keyword_item("dstip", rule_parsed.header.split(" ")[4][1:] if rule_parsed.header.split(" ")[
                          4].startswith("!") else rule_parsed.header.split(" ")[4], item_type="input"),
                      build_keyword_item("dstportallow",
                                         "!" if rule_parsed.header.split(" ")[5].startswith("!") else "-----"),
                      build_keyword_item("dstport",
                                         rule_parsed.header.split(" ")[5][1:] if rule_parsed.header.split(" ")[
                                             5].startswith("!") else rule_parsed.header.split(" ")[5],
                                         item_type="input"),
                      ]
    i = 0
    op_num = 0
    for op in rule_parsed.options:
        if op.name in ["msg", "sid"]:
            resppnse[op.name] = op.value
            i += 1
            continue
        if op.name == "metadata":
            for item in op.value.data:
                for meta_value in ["group ", "name ", "treatment ", "document ", "description "]:
                    if item.strip("'").strip().startswith(meta_value):
                        resppnse["metadata_" + meta_value.strip()] = item.replace(meta_value, "").strip("'").strip()
            continue
        rule_keywordss.append(build_keyword_item("keyword_selection" + str(op_num), op.name, x=op_num, y=0))

        if op.value:
            if op.value.startswith("!"):
                rule_keywordss.append(
                    build_keyword_item(f"keyword{str(op_num)}" + "-not", "!", x=op_num, y=0,
                                       item_type="input"))
                op.value = op.value[1:]
            rule_keywordss.append(
                build_keyword_item(f"keyword_selection{str(op_num)}" + "-data", op.value.strip('"').strip("'"), x=op_num, y=0,
                                   item_type="input"))
        op_num += 1
        i += 1
    for rule_key in rule_keywordss:
        resppnse["data"].append(
            {"htmlId": rule_key["htmlId"], "value": rule_key["value"], "typeOfItem": rule_key["typeOfItem"],
             "locationX": rule_key["locationX"], "locationY": rule_key["locationY"]})


def build_keyword_item(my_id, value, item_type="select", x=0, y=0):
    return {"htmlId": my_id, "value": value, "typeOfItem": item_type,
            "locationX": x, "locationY": y}


# build_rule_keyword_to_rule(None, SnortRule.objects.get(**{"id": 5}).content)
def build_rule_rule_to_keywords(request, rule_keywords=None):
    resppnse = {"fule_rule": ""}
    if not rule_keywords:
        rule_keywords = {}
    return JsonResponse(resppnse)

def favico(request):
    image_data = open(os.path.join(settings.BASE_DIR, "favicon.ico"), "rb").read()
    return HttpResponse(image_data, content_type="image/png")