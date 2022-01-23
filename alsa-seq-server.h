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

#ifndef _ALSA_SEQ_SERVER_H_
#define	_ALSA_SEQ_SERVER_H_

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>

#include <sys/queue.h>
#include <sys/types.h>

#include "asequencer.h"

#define	ASS_MAX_PORTS 16
#define	ASS_MAX_CLIENTS 32
#define	ASS_MAX_QUEUES 0
#define	ASS_MAX_FILTER 256

struct ass_parse {
	uint8_t *temp_cmd;
	uint8_t	temp_0[4];
	uint8_t	temp_1[4];
	uint8_t	state;
#define	ASS_ST_UNKNOWN	 0		/* scan for command */
#define	ASS_ST_1PARAM	 1
#define	ASS_ST_2PARAM_1	 2
#define	ASS_ST_2PARAM_2	 3
#define	ASS_ST_SYSEX_0	 4
#define	ASS_ST_SYSEX_1	 5
#define	ASS_ST_SYSEX_2	 6
};

#define	ASS_FIFO_MAX 1024

struct ass_fifo {
	unsigned int producer;
	unsigned int consumer;
	struct snd_seq_event data[ASS_FIFO_MAX];
};

struct ass_subscribers {
	struct snd_seq_port_subscribe info;
	TAILQ_ENTRY(ass_subscribers) src_entry;
	TAILQ_ENTRY(ass_subscribers) dst_entry;
	unsigned int ref_count;
};

struct ass_port_subs_info {
	TAILQ_HEAD(, ass_subscribers) head;
	unsigned int count;
	unsigned int exclusive:1;
};

struct ass_port;
typedef TAILQ_ENTRY(ass_port) ass_port_entry_t;
typedef TAILQ_HEAD(, ass_port) ass_port_head_t;

struct ass_port {
	struct snd_seq_addr addr;
	char	name[64];
	ass_port_entry_t entry;

	struct ass_port_subs_info c_src;
	struct ass_port_subs_info c_dst;

	unsigned int timestamping:1;
	unsigned int time_real:1;
	int	time_queue;

	unsigned int capability;
	unsigned int type;

	int	midi_channels;
	int	midi_voices;
	int	synth_voices;
};

struct ass_client;
typedef TAILQ_ENTRY(ass_client) ass_client_entry_t;
typedef TAILQ_HEAD(, ass_client) ass_client_head_t;

struct ass_client {
	ass_client_entry_t entry;
	ass_port_head_t head;
	snd_seq_client_type_t type;
	unsigned int accept_input:1;
	unsigned int accept_output:1;
	unsigned int rx_busy:1;
	unsigned int tx_busy:1;
	char	name[64];
	int	number;
	unsigned int filter;
	uint8_t	event_filter[256 / 8];
	int	event_lost;
	int	num_ports;
	int	convert32;
	struct ass_fifo rx_fifo;
	struct ass_parse parse;
	char *rx_name;
	char *tx_name;
	int	rx_fd;
	int	tx_fd;
};

extern ass_client_head_t ass_client_head;
extern void ass_lock(void);
extern void ass_unlock(void);
extern struct ass_client *ass_create_kernel_client(unsigned int, char *, char *);

/* Autodetect support */

extern void autodetect_init(void);
extern void autodetect_filter_add(const char *);

#endif		/* _ALSA_SEQ_SERVER_H_ */
