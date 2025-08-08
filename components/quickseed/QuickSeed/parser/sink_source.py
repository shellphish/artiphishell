JAVA_SOURCE_SINK_TABLE = {
    "source": ["fuzzerTestOneInput"],
    "sink": {
        "CommandInjection": [
            "Runtime",
            "ProcessBuilder",
            "exec"
        ],
        "Deserialization": [
            "ObjectInputStream",
            "readObject",
            "readObjective"
        ],
        "ExpressionLanguage": [
            "createValueExpression",
            "createMethodExpression",
            "buildConstraintViolationWithTemplate",
        ],
        "FileSystem": [
            "newBufferedReader",
            "newByteChannel",
            "readString",
            "newBufferedWriter",
            "readAllBytes",
            "readAllLines",
            "readSymbolicLink",
            "write",
            "writeString",
            "newInputStream",
            "newOutputStream",
            "open",
            "copy",
            "move",
            "FileReader",
            "FileWriter",
            "FileInputStream",
            "FileOutputStream",
            "Scanner",
        ],
        "LdapInjection": [
            "DirContext",
        ],
        "NamingContextLookup": [
            "lookup",
            "lookupLink",
        ],
        "ServerSideRequestForgery": [
            "SocksSocketImpl",
            "SocketChannel",
            "SocketAdapter",
            "PlainHttpConnection",
            "SocketImpl",
        ],
    }
}
