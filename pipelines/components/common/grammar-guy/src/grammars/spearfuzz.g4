```antlr
grammar spearfuzz;

// Entry point
spearfuzz : HEADER_SEPARATOR COOKIE_NAME '=' COOKIE_VALUE HEADER_SEPARATOR EOF;

// Tokens
HEADER_SEPARATOR : '\r\n' ;
COOKIE_NAME : 'uid' ;
COOKIE_VALUE : SHORT_COOKIE | MEDIUM_COOKIE | LONG_COOKIE | MEDIUM_COOKIE | LONG_COOKIE | MEDIUM_COOKIE | LONG_COOKIE | BASE64_COOKIE | INVALID_BASE64_COOKIE ;

fragment DIGIT : [0-9] ;
fragment ALPHA : [a-zA-Z] ;
fragment BASE64_CHAR : ALPHA | DIGIT | '+' | '/' ;
fragment SHORT_COOKIE : BASE64_CHAR{0,10} ; // Very short cookies
fragment MEDIUM_COOKIE : BASE64_CHAR{11,21} ; // Medium length cookies
fragment LONG_COOKIE : BASE64_CHAR{22,50} ; // Long cookies
fragment BASE64_COOKIE : BASE64_CHAR{51,100} ; // Very long cookies
fragment INVALID_BASE64_COOKIE : (ALPHA | DIGIT | '+' | '/' | '!'){22,100} ; // Invalid base64 characters including an invalid character '!'

WS : [ \t]+ -> skip ;
```