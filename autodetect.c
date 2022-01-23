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

#include <dirent.h>

#include "alsa-seq-server.h"

struct ass_filter;
typedef TAILQ_ENTRY(ass_filter) ass_filter_entry_t;
typedef TAILQ_HEAD(, ass_filter) ass_filter_head_t;

static ass_filter_head_t ass_filter_head = TAILQ_HEAD_INITIALIZER(ass_filter_head);

struct ass_filter {
	ass_filter_entry_t entry;
	const char *filter;
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

static void *
autodetect_watchdog(void *arg)
{
	struct ass_filter *pf;
	struct ass_client *pc;

	while (1) {
		char *devices[ASS_MAX_FILTER];
		bool found[ASS_MAX_FILTER];
		size_t count = 0;
		struct dirent *dp;
		DIR *dirp;
		char *str;

		dirp = opendir("/dev/");
		if (dirp == NULL)
			goto wait;

		while ((dp = readdir(dirp)) != NULL) {
			switch (dp->d_type) {
			case DT_CHR:
				if (asprintf(&str, "/dev/%s", dp->d_name) < 0)
					break;
				ass_lock();
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
				ass_unlock();

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

		ass_lock();
		TAILQ_FOREACH(pc, &ass_client_head, entry) {
			if (pc->type != KERNEL_CLIENT)
				continue;
			autodetect_find(devices, count, found, &pc->rx_name);
			autodetect_find(devices, count, found, &pc->tx_name);
		}
		ass_unlock();

		while (count--) {
			if (found[count] == true ||
			    ass_create_kernel_client(
			        SNDRV_SEQ_PORT_CAP_WRITE |
				SNDRV_SEQ_PORT_CAP_READ |
				SNDRV_SEQ_PORT_CAP_SYNC_READ |
				SNDRV_SEQ_PORT_CAP_SYNC_WRITE |
				SNDRV_SEQ_PORT_CAP_DUPLEX |
				SNDRV_SEQ_PORT_CAP_SUBS_READ |
				SNDRV_SEQ_PORT_CAP_SUBS_WRITE,
				devices[count], devices[count]) == NULL) {
				free(devices[count]);
			}
		}
	wait:
		usleep(4000000);
	}
}

void
autodetect_init(void)
{
	pthread_t td;

	if (TAILQ_FIRST(&ass_filter_head) == NULL)
		return;
	pthread_create(&td, NULL, &autodetect_watchdog, NULL);
}
