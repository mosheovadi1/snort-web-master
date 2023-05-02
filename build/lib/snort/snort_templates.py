
class snort_template():

    def __init__(self, protocol="tcp", src_port="any", dst_port="any", msg="{sig_group} {sig_name} - {sig_content}",
                 file_data=False, content=True, case_sensitive=False, sig_type="string", tag=True):
        tagged_content = 'content:"{sig_content}"; ' if content else ""
        tagged_file_data ="file_data; " if file_data else ""
        taggged_case_sensitive = "" if case_sensitive else "nocase; "
        metadata = 'team "{writer_team}", employee "{sig_writer}", group "{sig_group}", name "{sig_name}",' \
                   ' treatment "{main_doc}", keywords "None", date "{date}", document "{sig_ref}",' \
                   ' description "{sig_desc}"'
        tagged_tag = " tag:session,10,packets;" if tag else ""
        self.rule_string = f'alert {protocol} {src_port} any <> any {dst_port} (msg: "{msg};' \
                           f' {tagged_file_data}{tagged_content}{taggged_case_sensitive}' \
                           'sid:{sid}; rev:1;gid:1000000; metadata:type' + f' "{sig_type}", {metadata};)'

    def get_rule(self, sig_group, sig_name, sig_content, writer_team, sig_writer, main_doc, cur_date, sig_ref, sig_desc, sid=0):
        sig_content = sig_content.replace("\"", "\\\"")
        sig_desc = sig_desc.replace("\"", "\\\"")
        return self.rule_string.format(**{"sig_group": sig_group, "sig_name": sig_name, "sig_content": sig_content,
                                        "writer_team": writer_team, "sig_writer": sig_writer, "main_doc": main_doc,
                                        "date": cur_date, "sig_ref": sig_ref, "sig_desc": sig_desc, "sid": f"{sid}"})


class Preprocessor(snort_template):
    def __init__(self):
        super().__init__(protocol="ip", file_data=True, content=True)


class ipfull(snort_template):
    def __init__(self):
        super().__init__(src_port="any", msg="IP_RULE:{2}:IP_RULE", content="", nocase="", rule_type="ip")


snort_type_to_template = {"type a": ipfull,
                          "Preprocessor": Preprocessor}
EMPTY_TYPES = ["type b"]


types_list = list(zip(["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"][:len(snort_type_to_template.keys()) +1], snort_type_to_template.keys()))