# XPath 3.1 Nautilus Grammar
# Based on the ANTLR4 XPath31Parser grammar

# Entry point - complete XPath expression
ctx.rule("START", b"{XPATH}")

# Main XPath expression
ctx.rule("XPATH", b"{EXPR}")

# Expression alternatives
ctx.rule("EXPR", b"{EXPRSINGLE}")
ctx.rule("EXPR", b"{EXPRSINGLE},{EXPR}")

# Single expression alternatives
ctx.rule("EXPRSINGLE", b"{FOREXPR}")
ctx.rule("EXPRSINGLE", b"{LETEXPR}")
ctx.rule("EXPRSINGLE", b"{QUANTIFIEDEXPR}")
ctx.rule("EXPRSINGLE", b"{IFEXPR}")
ctx.rule("EXPRSINGLE", b"{OREXPR}")

# For expressions
ctx.rule("FOREXPR", b"for {SIMPLEFORBINDING} return {EXPRSINGLE}")
ctx.rule("FOREXPR", b"for {SIMPLEFORBINDING},{SIMPLEFORCLAUSE} return {EXPRSINGLE}")
ctx.rule("SIMPLEFORCLAUSE", b"{SIMPLEFORBINDING}")
ctx.rule("SIMPLEFORCLAUSE", b"{SIMPLEFORBINDING},{SIMPLEFORCLAUSE}")
ctx.rule("SIMPLEFORBINDING", b"${VARNAME} in {EXPRSINGLE}")

# Let expressions
ctx.rule("LETEXPR", b"let {SIMPLELETBINDING} return {EXPRSINGLE}")
ctx.rule("LETEXPR", b"let {SIMPLELETBINDING},{SIMPLELETCLAUSE} return {EXPRSINGLE}")
ctx.rule("SIMPLELETCLAUSE", b"{SIMPLELETBINDING}")
ctx.rule("SIMPLELETCLAUSE", b"{SIMPLELETBINDING},{SIMPLELETCLAUSE}")
ctx.rule("SIMPLELETBINDING", b"${VARNAME} := {EXPRSINGLE}")

# Quantified expressions
ctx.rule("QUANTIFIEDEXPR", b"some ${VARNAME} in {EXPRSINGLE} satisfies {EXPRSINGLE}")
ctx.rule("QUANTIFIEDEXPR", b"every ${VARNAME} in {EXPRSINGLE} satisfies {EXPRSINGLE}")
ctx.rule("QUANTIFIEDEXPR", b"some ${VARNAME} in {EXPRSINGLE},{QUANTBINDINGS} satisfies {EXPRSINGLE}")
ctx.rule("QUANTIFIEDEXPR", b"every ${VARNAME} in {EXPRSINGLE},{QUANTBINDINGS} satisfies {EXPRSINGLE}")
ctx.rule("QUANTBINDINGS", b"${VARNAME} in {EXPRSINGLE}")
ctx.rule("QUANTBINDINGS", b"${VARNAME} in {EXPRSINGLE},{QUANTBINDINGS}")

# If expressions
ctx.rule("IFEXPR", b"if ({EXPR}) then {EXPRSINGLE} else {EXPRSINGLE}")

# Logical expressions
ctx.rule("OREXPR", b"{ANDEXPR}")
ctx.rule("OREXPR", b"{ANDEXPR} or {OREXPR}")

ctx.rule("ANDEXPR", b"{COMPARISONEXPR}")
ctx.rule("ANDEXPR", b"{COMPARISONEXPR} and {ANDEXPR}")

# Comparison expressions
ctx.rule("COMPARISONEXPR", b"{STRINGCONCATEXPR}")
ctx.rule("COMPARISONEXPR", b"{STRINGCONCATEXPR} {GENERALCOMP} {STRINGCONCATEXPR}")
ctx.rule("COMPARISONEXPR", b"{STRINGCONCATEXPR} {VALUECOMP} {STRINGCONCATEXPR}")
ctx.rule("COMPARISONEXPR", b"{STRINGCONCATEXPR} {NODECOMP} {STRINGCONCATEXPR}")

# String concatenation
ctx.rule("STRINGCONCATEXPR", b"{RANGEEXPR}")
ctx.rule("STRINGCONCATEXPR", b"{RANGEEXPR} || {STRINGCONCATEXPR}")

# Range expressions
ctx.rule("RANGEEXPR", b"{ADDITIVEEXPR}")
ctx.rule("RANGEEXPR", b"{ADDITIVEEXPR} to {ADDITIVEEXPR}")

# Arithmetic expressions
ctx.rule("ADDITIVEEXPR", b"{MULTIPLICATIVEEXPR}")
ctx.rule("ADDITIVEEXPR", b"{MULTIPLICATIVEEXPR} + {ADDITIVEEXPR}")
ctx.rule("ADDITIVEEXPR", b"{MULTIPLICATIVEEXPR} - {ADDITIVEEXPR}")

ctx.rule("MULTIPLICATIVEEXPR", b"{UNIONEXPR}")
ctx.rule("MULTIPLICATIVEEXPR", b"{UNIONEXPR} * {MULTIPLICATIVEEXPR}")
ctx.rule("MULTIPLICATIVEEXPR", b"{UNIONEXPR} div {MULTIPLICATIVEEXPR}")
ctx.rule("MULTIPLICATIVEEXPR", b"{UNIONEXPR} idiv {MULTIPLICATIVEEXPR}")
ctx.rule("MULTIPLICATIVEEXPR", b"{UNIONEXPR} mod {MULTIPLICATIVEEXPR}")

# Union and intersect expressions
ctx.rule("UNIONEXPR", b"{INTERSECTEXCEPTEXPR}")
ctx.rule("UNIONEXPR", b"{INTERSECTEXCEPTEXPR} union {UNIONEXPR}")
ctx.rule("UNIONEXPR", b"{INTERSECTEXCEPTEXPR} | {UNIONEXPR}")

ctx.rule("INTERSECTEXCEPTEXPR", b"{INSTANCEOFEXPR}")
ctx.rule("INTERSECTEXCEPTEXPR", b"{INSTANCEOFEXPR} intersect {INTERSECTEXCEPTEXPR}")
ctx.rule("INTERSECTEXCEPTEXPR", b"{INSTANCEOFEXPR} except {INTERSECTEXCEPTEXPR}")

# Type expressions
ctx.rule("INSTANCEOFEXPR", b"{TREATEXPR}")
ctx.rule("INSTANCEOFEXPR", b"{TREATEXPR} instance of {SEQUENCETYPE}")

ctx.rule("TREATEXPR", b"{CASTABLEEXPR}")
ctx.rule("TREATEXPR", b"{CASTABLEEXPR} treat as {SEQUENCETYPE}")

ctx.rule("CASTABLEEXPR", b"{CASTEXPR}")
ctx.rule("CASTABLEEXPR", b"{CASTEXPR} castable as {SINGLETYPE}")

ctx.rule("CASTEXPR", b"{ARROWEXPR}")
ctx.rule("CASTEXPR", b"{ARROWEXPR} cast as {SINGLETYPE}")

# Arrow expressions
ctx.rule("ARROWEXPR", b"{UNARYEXPR}")
ctx.rule("ARROWEXPR", b"{UNARYEXPR} => {ARROWFUNCTIONSPECIFIER}{ARGUMENTLIST}")

ctx.rule("UNARYEXPR", b"{VALUEEXPR}")
ctx.rule("UNARYEXPR", b"+{VALUEEXPR}")
ctx.rule("UNARYEXPR", b"-{VALUEEXPR}")

ctx.rule("VALUEEXPR", b"{SIMPLEMAPEXPR}")

# Path expressions
ctx.rule("SIMPLEMAPEXPR", b"{PATHEXPR}")
ctx.rule("SIMPLEMAPEXPR", b"{PATHEXPR} ! {SIMPLEMAPEXPR}")

ctx.rule("PATHEXPR", b"/{RELATIVEPATHEXPR}")
ctx.rule("PATHEXPR", b"/")
ctx.rule("PATHEXPR", b"//{RELATIVEPATHEXPR}")
ctx.rule("PATHEXPR", b"{RELATIVEPATHEXPR}")

ctx.rule("RELATIVEPATHEXPR", b"{STEPEXPR}")
ctx.rule("RELATIVEPATHEXPR", b"{STEPEXPR}/{RELATIVEPATHEXPR}")
ctx.rule("RELATIVEPATHEXPR", b"{STEPEXPR}//{RELATIVEPATHEXPR}")

ctx.rule("STEPEXPR", b"{POSTFIXEXPR}")
ctx.rule("STEPEXPR", b"{AXISSTEP}")

ctx.rule("AXISSTEP", b"{FORWARDSTEP}{PREDICATELIST}")
ctx.rule("AXISSTEP", b"{REVERSESTEP}{PREDICATELIST}")

# Axis steps
ctx.rule("FORWARDSTEP", b"{FORWARDAXIS}{NODETEST}")
ctx.rule("FORWARDSTEP", b"{ABBREVFORWARDSTEP}")

ctx.rule("FORWARDAXIS", b"child::")
ctx.rule("FORWARDAXIS", b"descendant::")
ctx.rule("FORWARDAXIS", b"attribute::")
ctx.rule("FORWARDAXIS", b"self::")
ctx.rule("FORWARDAXIS", b"descendant-or-self::")
ctx.rule("FORWARDAXIS", b"following-sibling::")
ctx.rule("FORWARDAXIS", b"following::")
ctx.rule("FORWARDAXIS", b"namespace::")

ctx.rule("ABBREVFORWARDSTEP", b"{NODETEST}")
ctx.rule("ABBREVFORWARDSTEP", b"@{NODETEST}")

ctx.rule("REVERSESTEP", b"{REVERSEAXIS}{NODETEST}")
ctx.rule("REVERSESTEP", b"{ABBREVREVERSESTEP}")

ctx.rule("REVERSEAXIS", b"parent::")
ctx.rule("REVERSEAXIS", b"ancestor::")
ctx.rule("REVERSEAXIS", b"preceding-sibling::")
ctx.rule("REVERSEAXIS", b"preceding::")
ctx.rule("REVERSEAXIS", b"ancestor-or-self::")

ctx.rule("ABBREVREVERSESTEP", b"..")

# Node tests
ctx.rule("NODETEST", b"{KINDTEST}")
ctx.rule("NODETEST", b"{NAMETEST}")

ctx.rule("NAMETEST", b"{EQNAME}")
ctx.rule("NAMETEST", b"{WILDCARD}")

ctx.rule("WILDCARD", b"*")
ctx.rule("WILDCARD", b"{NCNAME}:*")
ctx.rule("WILDCARD", b"*:{NCNAME}")

# Primary expressions
ctx.rule("POSTFIXEXPR", b"{PRIMARYEXPR}")
ctx.rule("POSTFIXEXPR", b"{PRIMARYEXPR}{POSTFIXLIST}")

ctx.rule("POSTFIXLIST", b"{PREDICATE}")
ctx.rule("POSTFIXLIST", b"{ARGUMENTLIST}")
ctx.rule("POSTFIXLIST", b"{LOOKUP}")
ctx.rule("POSTFIXLIST", b"{PREDICATE}{POSTFIXLIST}")
ctx.rule("POSTFIXLIST", b"{ARGUMENTLIST}{POSTFIXLIST}")
ctx.rule("POSTFIXLIST", b"{LOOKUP}{POSTFIXLIST}")

ctx.rule("PRIMARYEXPR", b"{LITERAL}")
ctx.rule("PRIMARYEXPR", b"{VARREF}")
ctx.rule("PRIMARYEXPR", b"{PARENTHESIZEDEXPR}")
ctx.rule("PRIMARYEXPR", b"{CONTEXTITEMEXPR}")
ctx.rule("PRIMARYEXPR", b"{FUNCTIONCALL}")
ctx.rule("PRIMARYEXPR", b"{FUNCTIONITEMEXPR}")
ctx.rule("PRIMARYEXPR", b"{MAPCONSTRUCTOR}")
ctx.rule("PRIMARYEXPR", b"{ARRAYCONSTRUCTOR}")
ctx.rule("PRIMARYEXPR", b"{UNARYLOOKUP}")

# Literals
ctx.rule("LITERAL", b"{NUMERICLITERAL}")
ctx.rule("LITERAL", b"{STRINGLITERAL}")

ctx.rule("NUMERICLITERAL", b"{INTEGERLITERAL}")
ctx.rule("NUMERICLITERAL", b"{DECIMALLITERAL}")
ctx.rule("NUMERICLITERAL", b"{DOUBLELITERAL}")

# Variable references
ctx.rule("VARREF", b"${VARNAME}")
ctx.rule("VARNAME", b"{EQNAME}")

# Parenthesized expressions
ctx.rule("PARENTHESIZEDEXPR", b"({EXPR})")
ctx.rule("PARENTHESIZEDEXPR", b"()")

# Context item
ctx.rule("CONTEXTITEMEXPR", b".")

# Function calls
ctx.rule("FUNCTIONCALL", b"{EQNAME}{ARGUMENTLIST}")

ctx.rule("ARGUMENTLIST", b"()")
ctx.rule("ARGUMENTLIST", b"({ARGUMENT})")
ctx.rule("ARGUMENTLIST", b"({ARGUMENT},{ARGUMENTLIST_TAIL})")

ctx.rule("ARGUMENTLIST_TAIL", b"{ARGUMENT}")
ctx.rule("ARGUMENTLIST_TAIL", b"{ARGUMENT},{ARGUMENTLIST_TAIL}")

ctx.rule("ARGUMENT", b"{EXPRSINGLE}")
ctx.rule("ARGUMENT", b"?")

# Predicates
ctx.rule("PREDICATELIST", b"")
ctx.rule("PREDICATELIST", b"{PREDICATE}{PREDICATELIST}")

ctx.rule("PREDICATE", b"[{EXPR}]")

# Lookups
ctx.rule("LOOKUP", b"?{KEYSPECIFIER}")
ctx.rule("UNARYLOOKUP", b"?{KEYSPECIFIER}")

ctx.rule("KEYSPECIFIER", b"{NCNAME}")
ctx.rule("KEYSPECIFIER", b"{INTEGERLITERAL}")
ctx.rule("KEYSPECIFIER", b"{PARENTHESIZEDEXPR}")
ctx.rule("KEYSPECIFIER", b"*")

# Function items
ctx.rule("FUNCTIONITEMEXPR", b"{NAMEDFUNCTIONREF}")
ctx.rule("FUNCTIONITEMEXPR", b"{INLINEFUNCTIONEXPR}")

ctx.rule("NAMEDFUNCTIONREF", b"{EQNAME}#{INTEGERLITERAL}")

ctx.rule("INLINEFUNCTIONEXPR", b"function(){FUNCTIONBODY}")
ctx.rule("INLINEFUNCTIONEXPR", b"function({PARAMLIST}){FUNCTIONBODY}")
ctx.rule("INLINEFUNCTIONEXPR", b"function() as {SEQUENCETYPE}{FUNCTIONBODY}")
ctx.rule("INLINEFUNCTIONEXPR", b"function({PARAMLIST}) as {SEQUENCETYPE}{FUNCTIONBODY}")

ctx.rule("PARAMLIST", b"{PARAM}")
ctx.rule("PARAMLIST", b"{PARAM},{PARAMLIST}")

ctx.rule("PARAM", b"${EQNAME}")
ctx.rule("PARAM", b"${EQNAME} as {SEQUENCETYPE}")

ctx.rule("FUNCTIONBODY", b"\\{{EXPR}\\}")
ctx.rule("FUNCTIONBODY", b"\\{\\}")

# Map constructors
ctx.rule("MAPCONSTRUCTOR", b"map\\{\\}")
ctx.rule("MAPCONSTRUCTOR", b"map\\{{MAPCONSTRUCTORENTRY}\\}")
ctx.rule("MAPCONSTRUCTOR", b"map\\{{MAPCONSTRUCTORENTRY},{MAPENTRIES}\\}")

ctx.rule("MAPENTRIES", b"{MAPCONSTRUCTORENTRY}")
ctx.rule("MAPENTRIES", b"{MAPCONSTRUCTORENTRY},{MAPENTRIES}")

ctx.rule("MAPCONSTRUCTORENTRY", b"{EXPRSINGLE}:{EXPRSINGLE}")

# Array constructors
ctx.rule("ARRAYCONSTRUCTOR", b"{SQUAREARRAYCONSTRUCTOR}")
ctx.rule("ARRAYCONSTRUCTOR", b"{CURLYARRAYCONSTRUCTOR}")

ctx.rule("SQUAREARRAYCONSTRUCTOR", b"[]")
ctx.rule("SQUAREARRAYCONSTRUCTOR", b"[{EXPRSINGLE}]")
ctx.rule("SQUAREARRAYCONSTRUCTOR", b"[{EXPRSINGLE},{ARRAYITEMS}]")

ctx.rule("ARRAYITEMS", b"{EXPRSINGLE}")
ctx.rule("ARRAYITEMS", b"{EXPRSINGLE},{ARRAYITEMS}")

ctx.rule("CURLYARRAYCONSTRUCTOR", b"array\\{{EXPR}\\}")
ctx.rule("CURLYARRAYCONSTRUCTOR", b"array\\{\\}")

# Arrow function specifiers
ctx.rule("ARROWFUNCTIONSPECIFIER", b"{EQNAME}")
ctx.rule("ARROWFUNCTIONSPECIFIER", b"{VARREF}")
ctx.rule("ARROWFUNCTIONSPECIFIER", b"{PARENTHESIZEDEXPR}")

# Type system
ctx.rule("SINGLETYPE", b"{SIMPLETYPENAME}")
ctx.rule("SINGLETYPE", b"{SIMPLETYPENAME}?")

ctx.rule("SEQUENCETYPE", b"empty-sequence()")
ctx.rule("SEQUENCETYPE", b"{ITEMTYPE}")
ctx.rule("SEQUENCETYPE", b"{ITEMTYPE}?")
ctx.rule("SEQUENCETYPE", b"{ITEMTYPE}*")
ctx.rule("SEQUENCETYPE", b"{ITEMTYPE}+")

ctx.rule("ITEMTYPE", b"{KINDTEST}")
ctx.rule("ITEMTYPE", b"item()")
ctx.rule("ITEMTYPE", b"{FUNCTIONTEST}")
ctx.rule("ITEMTYPE", b"{MAPTEST}")
ctx.rule("ITEMTYPE", b"{ARRAYTEST}")
ctx.rule("ITEMTYPE", b"{ATOMICORUNIONTYPE}")
ctx.rule("ITEMTYPE", b"({ITEMTYPE})")

ctx.rule("ATOMICORUNIONTYPE", b"{EQNAME}")

# Kind tests
ctx.rule("KINDTEST", b"{DOCUMENTTEST}")
ctx.rule("KINDTEST", b"{ELEMENTTEST}")
ctx.rule("KINDTEST", b"{ATTRIBUTETEST}")
ctx.rule("KINDTEST", b"{SCHEMAELEMENTTEST}")
ctx.rule("KINDTEST", b"{SCHEMAATTRIBUTETEST}")
ctx.rule("KINDTEST", b"{PITEST}")
ctx.rule("KINDTEST", b"{COMMENTTEST}")
ctx.rule("KINDTEST", b"{TEXTTEST}")
ctx.rule("KINDTEST", b"{NAMESPACENODETEST}")
ctx.rule("KINDTEST", b"{ANYKINDTEST}")

ctx.rule("ANYKINDTEST", b"node()")
ctx.rule("DOCUMENTTEST", b"document-node()")
ctx.rule("DOCUMENTTEST", b"document-node({ELEMENTTEST})")
ctx.rule("DOCUMENTTEST", b"document-node({SCHEMAELEMENTTEST})")
ctx.rule("TEXTTEST", b"text()")
ctx.rule("COMMENTTEST", b"comment()")
ctx.rule("NAMESPACENODETEST", b"namespace-node()")
ctx.rule("PITEST", b"processing-instruction()")
ctx.rule("PITEST", b"processing-instruction({NCNAME})")
ctx.rule("PITEST", b"processing-instruction({STRINGLITERAL})")

ctx.rule("ATTRIBUTETEST", b"attribute()")
ctx.rule("ATTRIBUTETEST", b"attribute(*)")
ctx.rule("ATTRIBUTETEST", b"attribute({EQNAME})")
ctx.rule("ATTRIBUTETEST", b"attribute({EQNAME},{EQNAME})")
ctx.rule("ATTRIBUTETEST", b"attribute({EQNAME},{EQNAME}?)")

ctx.rule("SCHEMAATTRIBUTETEST", b"schema-attribute({EQNAME})")

ctx.rule("ELEMENTTEST", b"element()")
ctx.rule("ELEMENTTEST", b"element(*)")
ctx.rule("ELEMENTTEST", b"element({EQNAME})")
ctx.rule("ELEMENTTEST", b"element({EQNAME},{EQNAME})")
ctx.rule("ELEMENTTEST", b"element({EQNAME},{EQNAME}?)")

ctx.rule("SCHEMAELEMENTTEST", b"schema-element({EQNAME})")

ctx.rule("SIMPLETYPENAME", b"{EQNAME}")

# Function tests
ctx.rule("FUNCTIONTEST", b"{ANYFUNCTIONTEST}")
ctx.rule("FUNCTIONTEST", b"{TYPEDFUNCTIONTEST}")

ctx.rule("ANYFUNCTIONTEST", b"function(*)")

ctx.rule("TYPEDFUNCTIONTEST", b"function() as {SEQUENCETYPE}")
ctx.rule("TYPEDFUNCTIONTEST", b"function({SEQUENCETYPE}) as {SEQUENCETYPE}")
ctx.rule("TYPEDFUNCTIONTEST", b"function({SEQUENCETYPE},{SEQUENCETYPES}) as {SEQUENCETYPE}")

ctx.rule("SEQUENCETYPES", b"{SEQUENCETYPE}")
ctx.rule("SEQUENCETYPES", b"{SEQUENCETYPE},{SEQUENCETYPES}")

# Map tests
ctx.rule("MAPTEST", b"{ANYMAPTEST}")
ctx.rule("MAPTEST", b"{TYPEDMAPTEST}")

ctx.rule("ANYMAPTEST", b"map(*)")
ctx.rule("TYPEDMAPTEST", b"map({ATOMICORUNIONTYPE},{SEQUENCETYPE})")

# Array tests
ctx.rule("ARRAYTEST", b"{ANYARRAYTEST}")
ctx.rule("ARRAYTEST", b"{TYPEDARRAYTEST}")

ctx.rule("ANYARRAYTEST", b"array(*)")
ctx.rule("TYPEDARRAYTEST", b"array({SEQUENCETYPE})")

# Comparison operators
ctx.rule("GENERALCOMP", b"=")
ctx.rule("GENERALCOMP", b"!=")
ctx.rule("GENERALCOMP", b"<")
ctx.rule("GENERALCOMP", b"<=")
ctx.rule("GENERALCOMP", b">")
ctx.rule("GENERALCOMP", b">=")

ctx.rule("VALUECOMP", b"eq")
ctx.rule("VALUECOMP", b"ne")
ctx.rule("VALUECOMP", b"lt")
ctx.rule("VALUECOMP", b"le")
ctx.rule("VALUECOMP", b"gt")
ctx.rule("VALUECOMP", b"ge")

ctx.rule("NODECOMP", b"is")
ctx.rule("NODECOMP", b"<<")
ctx.rule("NODECOMP", b">>")

# Names and identifiers
ctx.rule("EQNAME", b"{QNAME}")
ctx.rule("EQNAME", b"{URIQUALIFIEDNAME}")
ctx.rule("EQNAME", b"{KEYWORD}")

ctx.rule("KEYWORD", b"ancestor")
ctx.rule("KEYWORD", b"ancestor-or-self")
ctx.rule("KEYWORD", b"and")
ctx.rule("KEYWORD", b"array")
ctx.rule("KEYWORD", b"as")
ctx.rule("KEYWORD", b"attribute")
ctx.rule("KEYWORD", b"cast")
ctx.rule("KEYWORD", b"castable")
ctx.rule("KEYWORD", b"child")
ctx.rule("KEYWORD", b"comment")
ctx.rule("KEYWORD", b"descendant")
ctx.rule("KEYWORD", b"descendant-or-self")
ctx.rule("KEYWORD", b"div")
ctx.rule("KEYWORD", b"document-node")
ctx.rule("KEYWORD", b"element")
ctx.rule("KEYWORD", b"else")
ctx.rule("KEYWORD", b"empty-sequence")
ctx.rule("KEYWORD", b"eq")
ctx.rule("KEYWORD", b"every")
ctx.rule("KEYWORD", b"except")
ctx.rule("KEYWORD", b"following")
ctx.rule("KEYWORD", b"following-sibling")
ctx.rule("KEYWORD", b"for")
ctx.rule("KEYWORD", b"function")
ctx.rule("KEYWORD", b"ge")
ctx.rule("KEYWORD", b"gt")
ctx.rule("KEYWORD", b"idiv")
ctx.rule("KEYWORD", b"if")
ctx.rule("KEYWORD", b"in")
ctx.rule("KEYWORD", b"instance")
ctx.rule("KEYWORD", b"intersect")
ctx.rule("KEYWORD", b"is")
ctx.rule("KEYWORD", b"item")
ctx.rule("KEYWORD", b"le")
ctx.rule("KEYWORD", b"let")
ctx.rule("KEYWORD", b"lt")
ctx.rule("KEYWORD", b"map")
ctx.rule("KEYWORD", b"mod")
ctx.rule("KEYWORD", b"namespace")
ctx.rule("KEYWORD", b"namespace-node")
ctx.rule("KEYWORD", b"ne")
ctx.rule("KEYWORD", b"node")
ctx.rule("KEYWORD", b"of")
ctx.rule("KEYWORD", b"or")
ctx.rule("KEYWORD", b"parent")
ctx.rule("KEYWORD", b"preceding")
ctx.rule("KEYWORD", b"preceding-sibling")
ctx.rule("KEYWORD", b"processing-instruction")
ctx.rule("KEYWORD", b"return")
ctx.rule("KEYWORD", b"satisfies")
ctx.rule("KEYWORD", b"schema-attribute")
ctx.rule("KEYWORD", b"schema-element")
ctx.rule("KEYWORD", b"self")
ctx.rule("KEYWORD", b"some")
ctx.rule("KEYWORD", b"text")
ctx.rule("KEYWORD", b"then")
ctx.rule("KEYWORD", b"treat")
ctx.rule("KEYWORD", b"union")

# Basic tokens
ctx.regex("QNAME", "[A-Za-z_][A-Za-z0-9_.-]*:[A-Za-z_][A-Za-z0-9_.-]*")
ctx.regex("URIQUALIFIEDNAME", "Q\\{[^\\}]*\\}[A-Za-z_][A-Za-z0-9_.-]*")
ctx.regex("NCNAME", "[A-Za-z_][A-Za-z0-9_.-]*")

# Literals
ctx.regex("STRINGLITERAL", "\"[^\"]*\"|'[^']*'")
ctx.regex("INTEGERLITERAL", "[0-9]+")
ctx.regex("DECIMALLITERAL", "[0-9]+\\.[0-9]+")
ctx.regex("DOUBLELITERAL", "[0-9]+\\.[0-9]+[eE][+-]?[0-9]+|[0-9]+[eE][+-]?[0-9]+")

# BAZINGA