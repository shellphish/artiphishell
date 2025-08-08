import json
import os

def parse_classes_in_scope():
    classes_json = json.load(open(f"{os.environ['OUT']}/antlr-out/classes_in_scope.json","r"))
    # the json structure is as follows {"in_scope_packages_from_antlr": "xyz", "all_packages_from_reachability_report": "", "sources_to_classes": {"xyz": "abc"}}
    # We only need the "in_scope_packages_from_antlr" key
    classes_string = classes_json["in_scope_packages_from_antlr"].replace(".**","")
    print(f"[DEBUG] Classes in scope: {classes_string}")
    open(f"{os.environ['OUT']}/antlr-out/classes_final","w").write(classes_string)
    # return "com,org"
    return classes_string

if __name__ == "__main__":
    assert os.path.exists(f"{os.environ['OUT']}/antlr-out/classes_in_scope.json"), "classes_in_scope.json not found"
    parse_classes_in_scope()