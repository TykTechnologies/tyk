package gateway 

/*
#include <stdlib.h>

typedef struct tyk_get_session_ret {
	char* session_buf;
	int buflen;
} tyk_get_session_ret;

struct tyk_get_session_ret* new_tyk_get_session_ret(char* session_buf, int buflen) {
	struct tyk_get_session_ret* ret = malloc(sizeof(struct tyk_get_session_ret));
	if(ret == NULL) {
		return NULL;
	}
	ret->session_buf=session_buf;
	ret->buflen=buflen;
	return ret;
};
*/
import "C"

func tykGetSessionRet(data []byte) *C.tyk_get_session_ret {
	sessionBuf := C.CBytes(data)
	length := C.int(len(data))
	return C.new_tyk_get_session_ret((*C.char)(sessionBuf), length)
}