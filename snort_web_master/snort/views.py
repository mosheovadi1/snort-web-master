import suricataparser
from django.http.response import HttpResponse, JsonResponse
from snort.models import SnortRule, SnortRuleViewArray
import json
import os
from django.conf import settings
from .parser import Parser
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
    rule_parsed = Parser(full_rule.replace("sid:-;", ""))
    build_keyword_dict(resppnse, rule_parsed)
    return JsonResponse(resppnse)


def get_current_user_name(request):
    return JsonResponse({"user": getattr(request.user, request.user.USERNAME_FIELD)})


def build_keyword_dict(resppnse, rule_parsed):
    if not rule_parsed:
        return
    rule_keywordss = [build_keyword_item("action", rule_parsed.header["action"]),
                      build_keyword_item("protocol", rule_parsed.header["proto"]),
                      build_keyword_item("srcipallow", "!" if not rule_parsed.header["source"][0] else "-----"),
                      build_keyword_item("srcip", rule_parsed.header["source"][1], item_type="input"),
                      build_keyword_item("srcportallow", "!" if not rule_parsed.header["src_port"][0] else "-----"),
                      build_keyword_item("srcport", rule_parsed.header["src_port"][1], item_type="input"),
                      build_keyword_item("direction", rule_parsed.header["arrow"]),
                      build_keyword_item("dstipallow", "!" if not rule_parsed.header["destination"][0] else "-----"),
                      build_keyword_item("dstip", rule_parsed.header["destination"][1], item_type="input"),
                      build_keyword_item("dstportallow","!" if not rule_parsed.header["dst_port"][0] else "-----"),
                      build_keyword_item("dstport",rule_parsed.header["dst_port"][1], item_type="input"),
                      ]
    i = 0
    op_num = 0
    for index, op in rule_parsed.options.items():
        if op[0] == "tag":
            if op[1] == ["session","packets 10"]:
                continue
        if op[0] in ["msg", "sid"]:
            resppnse[op[0]] = op[1]
            i += 1
            continue
        if op[0] == "metadata":
            for item in op[1]:
                for meta_value in ["group ", "name ", "treatment ", "document ", "description "]:
                    if item.strip("'").strip().startswith(meta_value):
                        resppnse["metadata_" + meta_value.strip()] = item.replace(meta_value, "").strip('"').strip()
                        break
            continue
        rule_keywordss.append(build_keyword_item("keyword_selection" + str(op_num), op[0], x=op_num, y=0))

        if len(op) > 1:
            i=0
            if isinstance(op[1], str):
                op = (op[0], [op[1]])
            for value in op[1]:
                name = f"keyword_selection{str(op_num)}"
                if i > 0:
                    name = f"keyword{op_num}-{i-1}"
                    rule_keywordss.append(build_keyword_item(name, value.split(":")[0].strip().strip('"').strip("'"), x=op_num, y=i-1))
                    value = value.split(":")[1]
                    i += 1
                if value.strip().startswith("!"):
                    rule_keywordss.append(
                        build_keyword_item(f"keyword{str(op_num)}" + "-not", "!", x=op_num, y=0,
                                           item_type="input"))
                    value = value.strip()[1:]

                rule_keywordss.append(
                    build_keyword_item(name + "-data", value.strip().strip('"').strip("'"), x=op_num, y=i,
                                       item_type="input"))
                i += 1
        op_num += 1

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