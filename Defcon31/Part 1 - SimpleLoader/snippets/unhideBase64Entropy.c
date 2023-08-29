#include <windows.h>
/****************************************************************/
/* This function is used to unhide a base64 string that was     */
/* generated using the encryptor_entropy.py generator           */
/* base64_unhide(sc, size, &sc_unhide, &sc_unhide_length);      */
/****************************************************************/
void base64_unhide(char *sc, int sc_length, char** sc_unhide, int* sc_unhide_length) {
	char* token;
	*sc_unhide_length = 0;
	token = strtok(sc, " ");
	*sc_unhide = calloc(sc_length, sizeof(char));
	while (token != NULL) {
		(*sc_unhide)[*sc_unhide_length] = token[0];
		*sc_unhide_length += 1;
		token = strtok(NULL, " ");
	}
	(*sc_unhide)[*sc_unhide_length] = '\0';
	char* tmp = *sc_unhide;
	*sc_unhide = realloc(tmp, *sc_unhide_length);
}