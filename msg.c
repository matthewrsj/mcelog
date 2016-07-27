#define _GNU_SOURCE 1
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "mcelog.h"
#include "msg.h"
#include "memutil.h"

enum syslog_opt syslog_opt = SYSLOG_REMARK;
int syslog_level = LOG_WARNING;
static FILE *output_fh;
static char *output_fn;

#ifdef CLEAR_TELEM
static FILE *telem_fh;
#endif /* CLEAR_TELEM */

int need_stdout(void)
{
	return !output_fh && (syslog_opt == 0);
}

int open_logfile(char *fn)
{
	output_fh = fopen(fn, "a");
	if (output_fh) { 
		char *old = output_fn;
		output_fn = xstrdup(fn);
		free(old);
		return 0;
	}
	return -1;
}

static void opensyslog(void)
{
	static int syslog_opened;
	if (syslog_opened)
		return;
	syslog_opened = 1;
	openlog("mcelog", 0, 0);
}

/* For warning messages that should reach syslog */
void Lprintf(char *fmt, ...)
{
	va_list ap;
	if (syslog_opt & SYSLOG_REMARK) { 
		va_start(ap, fmt);
		opensyslog();
		vsyslog(LOG_ERR, fmt, ap);
		va_end(ap);
	}
	if (output_fh || !(syslog_opt & SYSLOG_REMARK)) {
		va_start(ap, fmt);
		opensyslog();
		vfprintf(output_fh ? output_fh : stdout, fmt, ap);
		va_end(ap);
	}
}

/* For errors during operation */
void Eprintf(char *fmt, ...)
{
	FILE *f = output_fh ? output_fh : stderr;
	va_list ap;

	if (!(syslog_opt & SYSLOG_ERROR) || output_fh) {
		va_start(ap, fmt);
		fputs("mcelog: ", f);
		vfprintf(f, fmt, ap);
		if (*fmt && fmt[strlen(fmt)-1] != '\n')
			fputc('\n', f);
		va_end(ap);
	}
	if (syslog_opt & SYSLOG_ERROR) { 
		va_start(ap, fmt);
		opensyslog();
		vsyslog(LOG_ERR, fmt, ap);
		va_end(ap);
	}
}

void SYSERRprintf(char *fmt, ...)
{
	char *err = strerror(errno);
	va_list ap;
	FILE *f = output_fh ? output_fh : stderr;

	if (!(syslog_opt & SYSLOG_ERROR) || output_fh) {
		va_start(ap, fmt);
		fputs("mcelog: ", f);
		vfprintf(f, fmt, ap);
		fprintf(f, ": %s\n", err);
		va_end(ap);
	}
	if (syslog_opt & SYSLOG_ERROR) { 
		char *fmt2;
		va_start(ap, fmt);
		opensyslog();
		asprintf(&fmt2, "%s: %s\n", fmt, err);
		vsyslog(LOG_ERR, fmt2, ap);
		free(fmt2);
		va_end(ap);
	}
}

/* Write to syslog with line buffering */
static int vlinesyslog(char *fmt, va_list ap)
{
	static char line[200];
	int n;
	int lend = strlen(line); 
	int w = vsnprintf(line + lend, sizeof(line)-lend, fmt, ap);
	while (line[n = strcspn(line, "\n")] != 0) {
		line[n] = 0;
		syslog(syslog_level, "%s", line);
		memmove(line, line + n + 1, strlen(line + n + 1) + 1);
	}
	return w;
}

/* For decoded machine check output */
int Wprintf(char *fmt, ...)
{
	int n = 0;
	va_list ap;
	if (syslog_opt & SYSLOG_LOG) {
		va_start(ap,fmt);
		opensyslog();
		n = vlinesyslog(fmt, ap);
		va_end(ap);
	}
	if (!(syslog_opt & SYSLOG_LOG) || output_fh) {
		va_start(ap,fmt);
		n = vfprintf(output_fh ? output_fh : stdout, fmt, ap);
		va_end(ap);
	}
#ifdef CLEAR_TELEM
	if (telem_fh) {
		va_start(ap,fmt);
		vfprintf(telem_fh, fmt, ap);
		va_end(ap);
	}
#endif /* CLEAR_TELEM */
	return n;
}

/* For output that should reach both syslog and normal log */
void Gprintf(char *fmt, ...)
{
	va_list ap;
	if (syslog_opt & (SYSLOG_REMARK|SYSLOG_LOG)) {
		va_start(ap,fmt);
		vlinesyslog(fmt, ap);
		va_end(ap);
	}
	if (!(syslog_opt & SYSLOG_LOG) || output_fh) { 
		va_start(ap,fmt);
		vfprintf(output_fh ? output_fh : stdout, fmt, ap);
		va_end(ap);
	}
}

void flushlog(void)
{
	FILE *f = output_fh ? output_fh : stdout;
	fflush(f);
}

void reopenlog(void)
{
	if (output_fn && output_fh) { 
		fclose(output_fh);
		output_fh = NULL;
		if (open_logfile(output_fn) < 0) 
			SYSERRprintf("Cannot reopen logfile `%s'", output_fn);
	}	
}

#ifdef CLEAR_TELEM
#include <sys/stat.h>
#include <libgen.h>

int mkdir_p(const char *path, mode_t mode, char *cl)
{
	char *cl_base = NULL;

	if (!strcmp(path, ".") || !strcmp(path, "/") || !strcmp(path, "//") || !strcmp(path, "..")) {
		return 1;
	}

	cl = strdup(path);
	cl_base = dirname(cl);

	if (!mkdir_p(cl_base, mode, cl) && errno != EEXIST) {
		return 0;
	}

	return !((mkdir(path, mode) < 0 && errno != EEXIST));
}

int open_telem_file(const char *fn, char *mode)
{
	struct stat st = {0};
	int ret = 0;
	char *cl = NULL;
	char *dupfn = strdup(fn);
	char *dirn = dirname(dupfn);

	/* recursively create directories if directory does not exist */
	if (stat(dirn, &st) < 0 && !mkdir_p(dirn, 0755, cl)) {
		ret = -1;
		goto out;
	}

	telem_fh = fopen(fn, mode);
	if (telem_fh) {
		ret = 0;
		goto out;
	}

	ret = -1;

out:
	free(dupfn);
	free(cl);
	return ret;
}

int close_telem_file(void)
{
	if (telem_fh) {
		return fclose(telem_fh);
	}

	return -1;
}

#endif /* CLEAR_TELEM */
