from tree_sitter_languages import get_parser


def find_c_function(node, code):
    if node.type not in ["function_definition", "constructor_definition"]:
        return None

    declarator = node.child_by_field_name("declarator")
    if not declarator:
        return None

    identifier = declarator.child_by_field_name("declarator")
    if not identifier:
        return None

    name = next((x for x in identifier.children if x.type == "identifier"), None)
    if not name:
        name = identifier

    function_name = name.text.decode("utf-8")
    return function_name, node.start_point[0] + 1, node.end_point[0] + 1


def find_cpp_function(node, code):
    if node.type not in ["function_definition", "constructor_definition"]:
        return None

    declarator = node.child_by_field_name("declarator")
    if not declarator:
        return None

    identifier = declarator.child_by_field_name("declarator")
    if not identifier:
        return None

    if identifier.type == "qualified_identifier":
        name = identifier
    else:
        name = next((x for x in identifier.children if x.type == "identifier"), None)
        if not name:
            name = identifier

    function_name = name.text.decode("utf-8")
    return function_name, node.start_point[0] + 1, node.end_point[0] + 1


def find_java_function(node, code):
    if node.type not in ["method_declaration", "constructor_declaration"]:
        return None

    identifier = node.child_by_field_name("name")
    if not identifier:
        return None
    function_name = identifier.text.decode("utf-8")
    return function_name, node.start_point[0] + 1, node.end_point[0] + 1


def get_function_info(code, lang):
    parser = get_parser(lang)
    # parser.set_language(load_language(lang))

    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node

    functions = {}
    valid_types = {"c": find_c_function, "cpp": find_cpp_function, "java": find_java_function}

    def collect_functions(node):
        for child in node.children:
            collect_functions(child)
        result = valid_types[lang](node, code)
        if result is None:
            return
        function_name, line_start, line_end = result
        functions[function_name] = (line_start, line_end)

    collect_functions(root_node)
    return functions
