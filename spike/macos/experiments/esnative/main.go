//go:build darwin

// What does a Go program get when it asks for an Endpoint Security client?
// Needs cgo. See ../README in the PR for the results.
package main

/*
#cgo LDFLAGS: -lEndpointSecurity -lbsm
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>

static int try_client(void) {
	es_client_t *c = NULL;
	es_new_client_result_t r = es_new_client(&c, ^(es_client_t *cl, const es_message_t *m) {});
	if (r == ES_NEW_CLIENT_RESULT_SUCCESS) { es_delete_client(c); }
	return (int)r;
}
*/
import "C"

import (
	"fmt"
	"os"
)

func main() {
	names := map[int]string{0: "SUCCESS", 1: "ERR_INVALID_ARGUMENT", 2: "ERR_INTERNAL", 3: "ERR_NOT_ENTITLED", 4: "ERR_NOT_PERMITTED (no Full Disk Access)", 5: "ERR_NOT_PRIVILEGED (not root)", 6: "ERR_TOO_MANY_CLIENTS"}
	r := int(C.try_client())
	fmt.Printf("uid=%d es_new_client -> %d %s\n", os.Getuid(), r, names[r])
}
