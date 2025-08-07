
from difflib import SequenceMatcher
import re
from rich import print
from jinja2 import Template
import unicodedata
from unidecode import unidecode

def strip_ansi_codes(s):
    was_str = False
    if isinstance(s, str):
        s = s.encode('utf-8')
        was_str = True

    while True:
        new = re.sub(rb'\\x1b[^m]*m', b'', s)
        if new == s:
            break
        s = new

    if was_str:
        s = s.decode('utf-8')
    return s

def deemojify(inputString):
    returnString = ""

    for character in inputString:
        try:
            character.encode("ascii")
            returnString += character
        except UnicodeEncodeError:
            replaced = unidecode(str(character))
            if replaced != '':
                returnString += replaced
            else:
                try:
                     returnString += "[" + unicodedata.name(character) + "]"
                except ValueError:
                     returnString += "[x]"

    return returnString

def sanitize_output(s):
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')
    s = strip_ansi_codes(s)
    s = deemojify(s)
    return s


ROLE_COLORS = {
    'system': 'bold blue',
    'user': 'bold green',
    'assistant': 'bold yellow',
    'function': 'bold red',
    'tool': 'bold red',
}
def print_colored_messages(messages):
    for msg in messages:
        
        
        role = msg['role']
        if msg.get('function_call'):
            content = '# [bold]CONTENT[/bold]\n' + (msg.get('content', '') or '')+ '\n'
            content += '# [bold]FUNCTION_CALL[/bold]\n'
            content += f"[bold]{msg['function_call']['name']}[/bold](**{msg['function_call']['arguments']})"
        elif msg.get('tool_call'):
            content = '# [bold]CONTENT[/bold]\n' + (msg.get('content', '') or '')+ '\n'
            content += '# [bold]TOOL_CALL[/bold]\n'
            content += f"[bold]{msg['tool_call']['name']}[/bold](**{msg['tool_call']['arguments']})"
        else:
            if 'content' in msg:
                content = msg['content']
            else:
                # this is when we have a prompt template
                template = Template(msg['prompt_template'])
                content = template.render(**msg['prompt_args'])

        print(f"[{ROLE_COLORS[role]}]{'#'*40} {role} {'#' * 40}[/{ROLE_COLORS[role]}]\n{content}")

def print_choices_diff(result):
    start_content = None
    for choice in result['choices']:
        msg = choice['message']
        role = msg['role']
        content = msg['content']
        if start_content is None:
            print(f"[{ROLE_COLORS[role]}]{'#'*40} {role} {'#' * 40}[/{ROLE_COLORS[role]}]\n{content}")
            start_content = content
        else:
            print(f"[{ROLE_COLORS[role]}]{'#'*40} {role} {'#' * 40}[/{ROLE_COLORS[role]}]")
            diff = SequenceMatcher(None, start_content, content).get_opcodes()
            for i, (tag, i1, i2, j1, j2) in enumerate(diff):
                if tag == 'equal':
                    # print(f"[bold]{content[j1:j2]}[/bold]", end='')
                    pass
                elif tag == 'delete':
                    print(f"{i:03} [red]{content[j1:j2]}[/red]", end='')
                elif tag == 'insert':
                    print(f"{i:03} [green]{content[j1:j2]}[/green]", end='')
                elif tag == 'replace':
                    print(f"{i:03} [yellow]{content[j1:j2]}[/yellow]", end='')
