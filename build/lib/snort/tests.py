from django.test import TestCase

# Create your tests here.
from django.test import TestCase
from django.test.utils import setup_test_environment, teardown_test_environment
from django.test import Client
from django.core.serializers.json import DjangoJSONEncoder
import json
from django.urls import reverse
from snort.models import SnortRule, SnortRuleViewArray, attackGroup
from .views import get_rule_keys, get_rule, build_rule_keyword_to_rule, \
    build_keyword_item, build_keyword_dict, build_rule_rule_to_keywords
import requests

class SnortTestCase(TestCase):
    def setUp(self):
#        setup_test_environment()
        self.client = Client(json_encoder=DjangoJSONEncoder)

        self.at = attackGroup(name="atk")
        self.at.save()
        self.rule = SnortRule.objects.create(id=10, group=self.at, active=True, admin_locked=False, user="me", name="rule_name",
                                 content="alert TCP any any -> any any(msg: 65456;pcre: !'234234';sid:3; metadata: 'employee snort-master, group , name 65456, treatment , keywords 'None', date 1673248313409, document ,' description 345345345';)",
                                 description="desc", extra="extra", location="wtf", document="123", treatment="123",
                                 is_template=False, deleted=False)

    def tearDown(self) -> None:
        self.rule.delete()
        self.at.delete()


    def test_keyword_spliter(self):
        response = self.client.post(reverse('build_rule'), json.dumps({"fule_rule": self.rule.content}), content_type='application/json')
        response_json = response.json()["data"]
        response_metadata = response.json()
        result_expected = [{'htmlId': 'action', 'value': 'alert', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'protocol', 'value': 'TCP', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'srcipallow', 'value': '-----', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'srcip', 'value': 'any', 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'srcportallow', 'value': '-----', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'srcport', 'value': 'any', 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'direction', 'value': '->', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'dstipallow', 'value': '-----', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'dstip', 'value': 'any', 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'dstportallow', 'value': '-----', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'dstport', 'value': 'any', 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'keyword_selection0', 'value': 'pcre', 'typeOfItem': 'select', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'keyword0-not', 'value': '!', 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0},
                           {'htmlId': 'keyword_selection0-data', 'value': "'234234'", 'typeOfItem': 'input', 'locationX': 0, 'locationY': 0}]
        for d in response_json:
            if d not in result_expected:
                self.assertFalse(True, f"{d} is not an expected keyword")
        self.assertEqual(response_metadata.get('msg'), '65456')
        self.assertEqual(response_metadata.get('sid'), '3')
        self.assertEqual(response_metadata.get('metadata_name'), '65456')
        self.assertEqual(response_metadata.get('metadata_description'), '345345345')

    def test_delete_rule(self):
        self.rule.delete()
        self.assertTrue(self.rule.deleted)