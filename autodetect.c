/*-
 * Copyright (c) 2019-2022 Hans Petter Selasky <hselasky@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "alsa-seq-server.h"

struct ass_filter;
typedef TAILQ_ENTRY(ass_filter) ass_filter_entry_t;
typedef TAILQ_HEAD(, ass_filter) ass_filter_head_t;

static ass_filter_head_t ass_filter_head =
    TAILQ_HEAD_INITIALIZER(ass_filter_head);

struct ass_filter {
	ass_filter_entry_t entry;
	const char *filter;
};

struct ass_device;
typedef TAILQ_ENTRY(ass_device) ass_device_entry_t;
typedef TAILQ_HEAD(, ass_device) ass_device_head_t;

static ass_device_head_t ass_device_head =
    TAILQ_HEAD_INITIALIZER(ass_device_head);

struct ass_device {
	ass_device_entry_t entry;
	struct ass_client *client;
	char *rx_name;
	char *tx_name;
	char name[64];
	int rx_fd;
	int tx_fd;
	int unit;
	int subunit;
};

void
autodetect_filter_add(const char *name)
{
	struct ass_filter *pf;

	if (strncmp(name, "/dev/", 5) == 0)
		name += 5;

	pf = malloc(sizeof(*pf));
	pf->filter = name;

	TAILQ_INSERT_TAIL(&ass_filter_head, pf, entry);
}

static int
autodetect_compare(const void *a, const void *b)
{
	const char *pa = *(const void * const *)a;
	const char *pb = *(const void * const *)b;

	return (strcmp(pa, pb));
}

static void
autodetect_find(char **pp, size_t num, bool *pfound, char **name)
{
	if (*name == NULL)
		return;
	name = bsearch(name, pp, num, sizeof(pp[0]), &autodetect_compare);
	if (name == NULL)
		return;
	pfound[name - pp] = true;
}

static void
device_watchdog(struct ass_device *pd)
{
	int fd;
	bool any = false;

	if (pd->rx_name == NULL) {
		/* do nothing */
	} else if (pd->rx_fd < 0) {
		fd = open(pd->rx_name, O_RDONLY | O_NONBLOCK);
		if (fd > -1) {
			pd->rx_fd = fd;
			fcntl(pd->rx_fd, F_SETFL, (int)O_NONBLOCK);
			any = true;
		}
	} else {
		if (fcntl(pd->rx_fd, F_SETFL, (int)O_NONBLOCK) == -1) {
			DPRINTF("Close read\n");
			close(pd->rx_fd);
			pd->rx_fd = -1;
			any = true;
		}
	}

	if (pd->tx_name == NULL) {
		/* do nothing */
	} else if (pd->tx_fd < 0) {
		fd = open(pd->tx_name, O_WRONLY | O_NONBLOCK);
		if (fd > -1) {
			pd->tx_fd = fd;
			fcntl(pd->tx_fd, F_SETFL, (int)0);
			any = true;
		}
	} else {
		if (fcntl(pd->tx_fd, F_SETFL, (int)0) == -1) {
			DPRINTF("Close write\n");
			close(pd->tx_fd);
			pd->tx_fd = -1;
			any = true;
		}
	}

	if (any) {
		/* free old client, if any */
		if (pd->client != NULL) {
			ass_free_client(pd->client);
			pd->client = NULL;
		}

		/* check that all devices are present */
		any = (pd->tx_name == NULL || pd->tx_fd > -1) &&
		      (pd->rx_name == NULL || pd->rx_fd > -1);
	}

	if (any) {
		const char *pname = NULL;

		pd->unit = -1;
		pd->subunit = 0;

		if (pd->rx_name != NULL) {
			if (strncmp(pd->rx_name, "/dev/", 5) == 0) {
				pname = pd->rx_name + 5;
				sscanf(pd->rx_name, "/dev/umidi%d.%d", &pd->unit, &pd->subunit);
			} else {
				pname = pd->rx_name;
			}
		} else {
			if (strncmp(pd->tx_name, "/dev/", 5) == 0) {
				pname = pd->tx_name + 5;
				sscanf(pd->tx_name, "/dev/umidi%d.%d", &pd->unit, &pd->subunit);
			} else {
				pname = pd->tx_name;
			}
		}

		if (pd->unit > -1) {
			size_t size = sizeof(pd->name);

			/* create sysctl name */
			snprintf(pd->name, sizeof(pd->name), "dev.uaudio.%d.%%desc", pd->unit);

			/* lookup sysctl */
			if (sysctlbyname(pd->name, pd->name, &size, NULL, 0) == 0 ||
			    (errno == ENOMEM)) {
				char *ptr;

				/* check string length */
				if (size > sizeof(pd->name) - 1)
					size = sizeof(pd->name) - 1;

				/* zero terminate */
				pd->name[size] = 0;

				/* split */
				ptr = strchr(pd->name, ',');
				if (ptr != NULL) {
					size = ptr - pd->name;
					*ptr = 0;
				}
				/* limit the string length */
				if (strlen(pd->name) > 16) {
					pd->name[16] = 0;
					size = 16;
				}
			} else {
				strlcpy(pd->name, pname, sizeof(pd->name));
			}
		} else {
			strlcpy(pd->name, pname, sizeof(pd->name));
		}

		/* try to create a new kernel client. */
		pd->client =
		    ass_create_kernel_client(pd->rx_fd, pd->tx_fd, pd->name, pd->subunit);
	}
}

void *
autodetect_watchdog(void *arg)
{
	struct ass_filter *pf;
	struct ass_device *pd;

	while (1) {
		char *devices[ASS_MAX_FILTER];
		bool found[ASS_MAX_FILTER];
		size_t count = 0;
		struct dirent *dp;
		DIR *dirp;
		char *str;

		if (TAILQ_FIRST(&ass_filter_head) == NULL)
			goto wait;

		dirp = opendir("/dev/");
		if (dirp == NULL)
			goto wait;

		while ((dp = readdir(dirp)) != NULL) {
			switch (dp->d_type) {
			case DT_CHR:
				if (asprintf(&str, "/dev/%s", dp->d_name) < 0)
					break;
				if (count < ASS_MAX_FILTER) {
					TAILQ_FOREACH(pf, &ass_filter_head, entry) {
						if (strstr(dp->d_name, pf->filter) ==
						    dp->d_name) {
							found[count] = false;
							devices[count] = str;
							count++;
							str = NULL;
							break;
						}
					}
				}
				free(str);
				break;
			default:
				break;
			}
		}
		closedir(dirp);

		if (count == 0)
			goto wait;

		mergesort(devices, count, sizeof(devices[0]), &autodetect_compare);

		TAILQ_FOREACH(pd, &ass_device_head, entry) {
			autodetect_find(devices, count, found, &pd->rx_name);
			autodetect_find(devices, count, found, &pd->tx_name);
		}

		while (count--) {
			if (found[count] == true ||
			    new_device(devices[count], devices[count]) != 0)
				free(devices[count]);
		}
	wait:
		TAILQ_FOREACH(pd, &ass_device_head, entry)
			device_watchdog(pd);

		usleep(1000000);
	}
}

int
new_device(char *rx_name, char *tx_name)
{
	struct ass_device *pd;

	pd = malloc(sizeof(*pd));
	if (pd == NULL)
		return (ENOMEM);

	memset(pd, 0, sizeof(*pd));

	pd->rx_name = rx_name;
	pd->tx_name = tx_name;
	pd->rx_fd = -1;
	pd->tx_fd = -1;

	TAILQ_INSERT_TAIL(&ass_device_head, pd, entry);
	return (0);
}
