import re as _re
import subprocess as _subprocess
import typing as _typ


JAZZER_STANDALONE_JAR = "/shellphish/jazzer_standalone.jar"
JAZZZER_CLASS_NAME = "com.code_intelligence.jazzer.Jazzer"
JAZZER_ENTRYPOINT = "fuzzerTestOneInput"

JDB_NAME = "jdb"
JDB_VERSION_FLAG = "-version"

JDB_DEFAULT_EXCLUDED = ["java.*","javax.*","sun.*","com.sun.*","jdk.*"]

JAVA_DEBUG_CMD = "java -Xdebug -Xrunjdwp:transport=dt_socket,address={port},server=y,suspend=y"

REGEXP_PATT_VERSION = r"^[0-9]+(\.[0-9]+(\.[0-9]+)?)?$"
REGEXP_PATT_CSV = r"\".*?\"|'.*?'|[^,]+"
REGEXP_PROMPT = r"main\[\d+\]"

# See below for information on string patterns of jdb output
# https://github.com/openjdk/jdk/blob/master/src/jdk.jdi/share/classes/com/sun/tools/example/debug/tty/TTYResources.java

REGEXP_PATT_STEP_EXPECT = (r"(Exception occurred:|((Step completed:|Method entered:\r\n"
                           r"Step completed:|Method entered: )"
                           r"|Method exited: [^,]+, ))[^\r\n]+\r\n([^\r\n]+\r\n)*")

REGEXP_PATT_STEP_COMPLETED = (r"(Step completed:|Method entered:|"
                              r"Method exited: return value = ([^,]+),) "
                              r"\"thread=([^\"]*)\", "
                              r"([^.]+(\.[^.]+)+\(\)), "
                              r"line=([0-9]+) bci=([0-9]+)")

REGEXP_PATT_LINE_LISTING = r"\n([0-9]+)\s+([^\r\n]+)\r\n"

REGEXP_PATT_BACKTRACE = r"\[(\d+)\] ([\w.$<>]+(?: [\w.$<>]+)*) \(([\w.$: -]+)\)"


# Compiled regular expressions

REGEXP_CSV = _re.compile(REGEXP_PATT_CSV)
REGEXP_STEP_COMPLETED = _re.compile(REGEXP_PATT_STEP_COMPLETED)
REGEXP_LINE_LISTING = _re.compile(REGEXP_PATT_LINE_LISTING)
REGEXP_BACKTRACE = _re.compile(REGEXP_PATT_BACKTRACE)


def make_matcher(regexp: str) -> _typ.Callable[[str], bool]:
    """
    Returns a helper function that will return `True` when provided with a
    string that matches the provided `regexp` pattern, and `False`
    otherwise.

    :param regexp: The regular expression against which to match strings.
    :return: The helper function that will check strings against the pattern.
    """

    p = _re.compile(regexp)

    def reject(s):
        return p.match(s) is not None

    return reject


def filter_regexp(regexp: str, lst: _typ.Iterator[str]) -> _typ.Iterator[str]:
    """
    Filters a list of strings `lst` to only retain those which match the
    regular expression provided through `regexp`.

    :param regexp: The regular expression against which to match strings.
    :param lst: An iterator of strings to filter.
    :return: An iterator of strings that have been filtered by `regexp`.
    """

    return filter(make_matcher(regexp), lst)


def head(it: _typ.Iterable) -> _typ.Optional[_typ.Any]:
    # Convert list to iterator if necessary
    try:
        new_it = (x for x in it)
        it = new_it
    except:
        raise

    # Try to get next element of iterator
    try:
        return it.__next__()
    except AttributeError:
        raise
        # NoneType provided
        return None
    except NameError:
        # Not an iterator
        return None
    except StopIteration:
        # Iterator empty
        return None


def parse_jdb_version() -> _typ.Optional[str]:
    """
    Returns the version of `jdb` if the command is available and in the
    PATH; returns `None` otherwise.

    :return: The version of `jdb` as a string.
    """
    try:
        version_str = _subprocess.run(
            [JDB_NAME, JDB_VERSION_FLAG], stdout=_subprocess.PIPE
        ).stdout.decode("utf-8")

    except FileNotFoundError:
        return None

    version = head(filter_regexp(regexp=REGEXP_PATT_VERSION, lst=version_str.split()))

    return version


def parse_jdb_value(value: str) -> _typ.Any:
    """
    Returns a Python-typed value given a string parsed from `jdb`
    output. Supports strings, characters, integers, floats and
    boolean values.

    :param value: The `jdb` value as a string.
    :return: The value as a Python type.
    """

    # Assume we are dealing with a string that can be sliced/diced
    if type(value) is not str:
        return value

    # Void value
    if value == "<void value>":
        return None

    # Objects should not be modified for the moment
    # NOTE: Could expand arrays (or simple types of arrays)
    if value[0:8] == "instance":
        return value

    # Arrays
    if value[0] == "{" and value[-1] == "}":

        # NOTE: below did not work, because quotes were not saved
        # which interfered with the string vs int detection
        # #csv_like_data = [value[1:-1].strip()]
        # #csv_reader = _csv.reader(csv_like_data, skipinitialspace=True)
        # #return list(map(parse_jdb_value, _itertools.chain(*csv_reader)))

        data = value[1:-1].strip()
        values = map(str.strip, REGEXP_CSV.findall(data))
        return list(map(parse_jdb_value, values))

    # NoneType
    if value == "null":
        return None

    # Quoted string
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]

    # Boolean type
    if value in ["true", "false"]:
        return value == "true"

    # We may have an int or a float, so test in least restrictive order
    try:
        return int(value)
    except ValueError:
        pass

    try:
        return float(value)
    except ValueError:
        pass

    # Unknown type
    return value


def parse_jdb_values(text: str) -> _typ.Dict[str, _typ.Any]:
    """
    Returns a dictionary of Python-typed values, given a list of
    variables as produced by `jdb`'s output of a command such as
    `locals`---that is, one line per variable, with the name and
    value separated by an '=' character.

    :param text: The output from `jdb`.
    :return: A dictionary of parsed variables.
    """
    # Remove /r
    text = text.replace("\r\n", "\n")

    # Strip trailing spaces
    text = text.strip()

    # Split into lines
    lines = text.splitlines()

    # Parse each line
    variables = []
    for line in lines:
        if "=" not in line:
            continue

        parts = line.split(sep="=", maxsplit=1)
        name = parts[0].strip()
        value = parts[1].strip()

        parsed_value = parse_jdb_value(value)

        variables.append((name, parsed_value))

    # Turn the list into a dict
    # >variables_dict = _collections.OrderedDict(variables)
    variables_dict = dict(variables)

    return variables_dict


def parse_jdb_step(text: str) -> _typ.Dict[str, _typ.Any]:
    """

    :param text:
    :return:
    """
    # Currently we don't extract information on exceptions
    # (Exception occurred: java.lang.ArrayIndexOutOfBoundsException
    #  (uncaught)"thread=main", Ordered.main(), line=20 bci=9)
    if "Exception occurred:" in text:
        return None

    info = {}

    # Use regular expressions to parse data
    res_location = head(REGEXP_STEP_COMPLETED.findall(text))
    res_line = head(REGEXP_LINE_LISTING.findall(text))

    # Complete metadata accordingly
    if res_location is not None:
        # (title, return, thread, Class.method(), .method, line, bci)

        # Return values because we have "trace methods 1"
        if res_location[1] != "":
            info["return"] = parse_jdb_value(res_location[1])

        info["thread"] = res_location[2]
        info["class.method"] = res_location[3]
        info["method"] = res_location[4][1:]
        info["line"] = res_location[5]
        info["bci"] = res_location[6]

    if res_line is not None:
        info["line"] = res_line[0]
        info["instruction"] = res_line[1]

    # Parse values
    try:
        if "line" in info:
            info["line"] = int(info["line"])
        if "bci" in info:
            info["bci"] = int(info["bci"])
        if "return" in info:
            info["return"] = parse_jdb_value(info["return"])
    except ValueError:
        pass

    return info if len(info) > 0 else None

def parse_jdb_backtrace(text: str) -> list[dict]:
    """
    Parse the backtrace output from jdb.
    """
    backtrace_frames = []
    for frame_line in text.strip().split("\r\n"):
        obj = REGEXP_BACKTRACE.match(frame_line.strip())
        if obj:
            idx, function, location = obj.groups()
            backtrace_frames.append({
                "index": int(idx),
                "function": function,
                "location": location
            })

    print("backtrace_frames", backtrace_frames)
    return backtrace_frames
