#define ARRAY_LEN(X) (sizeof(X) / sizeof(X[0]))
#define WIDTH_OF(TYPE,FIELD) (sizeof(((TYPE*)0)->FIELD))
#define OFFSET_OF(TYPE,FIELD) (((char *)&((TYPE*)0)->FIELD) - (char*)NULL)
