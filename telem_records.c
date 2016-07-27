#ifdef CLEAR_TELEM
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include "mcelog.h"

#define TELEMETRY_LIB "/usr/lib64/libtelemetry.so.3"

void *tm_dlhandle;

struct telem_ref {
	struct telem_record *record;
};

int (*tm_create_record)(struct telem_ref **, uint32_t, char *, uint32_t);
int (*tm_set_payload)(struct telem_ref *, char *);
int (*tm_send_record)(struct telem_ref *);
void (*tm_free_record)(struct telem_ref *);

/* attempt to load libtelemetry functions */
int load_telem_api(void)
{
	char *error;

	tm_dlhandle = dlopen(TELEMETRY_LIB, RTLD_NOW);
	if (!tm_dlhandle) {
		/* No error, we just don't have telemetry */
		return 0;
	}

	tm_create_record = dlsym(tm_dlhandle, "tm_create_record");
	if ((error = dlerror()) != NULL) {
		SYSERRprintf("%s", error);
		dlclose(tm_dlhandle);
		return 0;
	}

	tm_set_payload = dlsym(tm_dlhandle, "tm_set_payload");
	if ((error = dlerror()) != NULL) {
		SYSERRprintf("%s", error);
		dlclose(tm_dlhandle);
		return 0;
	}

	tm_send_record = dlsym(tm_dlhandle, "tm_send_record");
	if ((error = dlerror()) != NULL) {
		SYSERRprintf("%s", error);
		dlclose(tm_dlhandle);
		return 0;
	}

	tm_free_record = dlsym(tm_dlhandle, "tm_free_record");
	if ((error = dlerror()) != NULL) {
		SYSERRprintf("%s", error);
		dlclose(tm_dlhandle);
		return 0;
	}

	return 1;
}

/* wrapper to be used in mcelog.c without including the dlfcn library */
void unload_telem_api(void)
{
	dlclose(tm_dlhandle);
}

/* send record to telemetry server
 * only called if load_telem_api is successful
 */
int send_record(int severity, char *class, char *payload_fn)
{
	struct telem_ref *handle = NULL;
	struct stat st;
	FILE   *fp = NULL;
	int    ret = 0;
	char   *payload = NULL, *classification = NULL;
	long   fsize = 0, bytes_read = 0;

	/* open telem file to read */
	fp = fopen(payload_fn, "r");
	if (!fp) {
		SYSERRprintf("Could not open %s for mce telemetry", payload_fn);
		ret = -1;
		goto out;
	}

	/* find the size of the record and allocate memory */
	if (fstat(fileno(fp), &st) < 0) {
		SYSERRprintf("fstat error on %s", payload_fn);
		ret = -1;
		goto out;
	}

	if (!st.st_size) {
		SYSERRprintf("MCE telemetry record %s empty", payload_fn);
		ret = -1;
		goto out;
	}

	fsize = st.st_size;

	payload = (char *) malloc(fsize + 1);

	/* read the payload from the record file */
	bytes_read = fread(payload, (size_t) fsize, 1, fp);

	if (!bytes_read) {
		SYSERRprintf("Could not read payload for mce telemetry");
		ret = -1;
		goto out;
	}

	/* make sure payload ends with a null char,
	 * without this, occasional tm_set_payload errors occur
	 */
	payload[fsize - 1] = '\0';

	/* create telemetry record with severity and classification
	 * this call should fail silently since it will fail if the user is
	 * opted out - this should not be reported as an error.
	 * A return greater than 0 indicates this should be a silent failure by
	 * the calling function.
	 */
	asprintf(&classification, "org.clearlinux/mce/%s", class);

	if (tm_create_record(&handle, severity, classification, 1) < 0) {
		ret = 1;
		goto out;
	}

	/* set the payload for the telemetry record from the payload read
	 * from the temporary telemetry logfile
	 * if we made it this far, the user was opted in, fail loudly
	 */
	if (tm_set_payload(handle, payload) < 0) {
		SYSERRprintf("Cannot set telemetry payload in mcelog");
		ret = -1;
		goto out;
	}

	/* send the record to the telemetry server set in the user's telemetry
	 * configuration files
	 */
	if (tm_send_record(handle) < 0 ) {
		SYSERRprintf("Cannot send telemetry record in mcelog");
		ret = -1;
		goto out;
	}

	/* clean up: free the record, free the payload, close the file */
	ret = 0;

out:
	if (handle) {
		tm_free_record(handle);
	}

	if (payload) {
		free(payload);
	}

	if (fp) {
		fclose(fp);
	}

	return ret;
}
#endif /* CLEAR_TELEM */
