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

/*
 *  Based on ALSA sequencer Client Manager
 *  Copyright (c) 1998-2001 by Frank van de Pol <fvdpol@coil.demon.nl>
 *			       Jaroslav Kysela <perex@perex.cz>
 *			       Takashi Iwai <tiwai@suse.de>
 */

/*
 *   Based on ALSA sequencer Ports
 *   Copyright (c) 1998 by Frank van de Pol <fvdpol@coil.demon.nl>
 *			   Jaroslav Kysela <perex@perex.cz>
 */

#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <err.h>
#include <pwd.h>
#include <poll.h>
#include <limits.h>
#include <sysexits.h>

#include <cuse.h>

#include "alsa-seq-server.h"

#include <sys/errno.h>
#include <sys/sysctl.h>

static pthread_mutex_t ass_mtx;
static pthread_cond_t ass_cv;
static uid_t uid;
static gid_t gid;
static mode_t mode = 0666;
static const char *dname = "snd/seq";
static bool background;

ass_client_head_t ass_client_head =
    TAILQ_HEAD_INITIALIZER(ass_client_head);

static const uint8_t ass_cmd_to_len[16] = {
	[0x0] = 0,			/* reserved */
	[0x1] = 0,			/* reserved */
	[0x2] = 2,			/* bytes */
	[0x3] = 3,			/* bytes */
	[0x4] = 3,			/* bytes */
	[0x5] = 1,			/* bytes */
	[0x6] = 2,			/* bytes */
	[0x7] = 3,			/* bytes */
	[0x8] = 3,			/* bytes */
	[0x9] = 3,			/* bytes */
	[0xA] = 3,			/* bytes */
	[0xB] = 3,			/* bytes */
	[0xC] = 2,			/* bytes */
	[0xD] = 2,			/* bytes */
	[0xE] = 3,			/* bytes */
	[0xF] = 1,			/* bytes */
};

#ifdef HAVE_DEBUG
#define	DPRINTF(fmt, ...) printf("%s:%d: " fmt, __FUNCTION__, __LINE__,## __VA_ARGS__)
#else
#define	DPRINTF(fmt, ...) do { } while (0)
#endif

static void
ass_init(void)
{
	pthread_mutex_init(&ass_mtx, NULL);
	pthread_cond_init(&ass_cv, NULL);
}

void
ass_lock(void)
{
	pthread_mutex_lock(&ass_mtx);
}

void
ass_unlock(void)
{
	pthread_mutex_unlock(&ass_mtx);
}

static void
ass_wait(void)
{
	pthread_cond_wait(&ass_cv, &ass_mtx);
}

static void
ass_wakeup(void)
{
	pthread_cond_broadcast(&ass_cv);
	cuse_poll_wakeup();
}

static uid_t
ass_id(const char *name, const char *type)
{
	uid_t val;
	char *ep;

	val = strtoul(name, &ep, 10);
	if (*ep != '\0')
		errx(EX_USAGE, "%s: illegal %s name", name, type);
	return (val);
}

static void
ass_uid(const char *s)
{
	struct passwd *pw;

	uid = ((pw = getpwnam(s)) != NULL) ? pw->pw_uid : ass_id(s, "user");
}

static void
ass_gid(const char *s)
{
	struct passwd *pw;

	gid = ((pw = getpwnam(s)) != NULL) ? pw->pw_gid : ass_id(s, "group");
}

/*
 * The following statemachine, that converts MIDI commands to
 * USB MIDI packets, derives from Linux's usbmidi.c, which
 * was written by "Clemens Ladisch":
 *
 * Returns:
 *    0: No command
 * Else: Command is complete
 */
static uint8_t
ass_midi_convert(struct ass_parse *parse, uint8_t cn, uint8_t b)
{
	uint8_t p0 = (cn << 4);

	if (b >= 0xf8) {
		parse->temp_0[0] = p0 | 0x0f;
		parse->temp_0[1] = b;
		parse->temp_0[2] = 0;
		parse->temp_0[3] = 0;
		parse->temp_cmd = parse->temp_0;
		return (1);

	} else if (b >= 0xf0) {
		switch (b) {
		case 0xf0:		/* system exclusive begin */
			parse->temp_1[1] = b;
			parse->state = ASS_ST_SYSEX_1;
			break;
		case 0xf1:		/* MIDI time code */
		case 0xf3:		/* song select */
			parse->temp_1[1] = b;
			parse->state = ASS_ST_1PARAM;
			break;
		case 0xf2:		/* song position pointer */
			parse->temp_1[1] = b;
			parse->state = ASS_ST_2PARAM_1;
			break;
		case 0xf4:		/* unknown */
		case 0xf5:		/* unknown */
			parse->state = ASS_ST_UNKNOWN;
			break;
		case 0xf6:		/* tune request */
			parse->temp_1[0] = p0 | 0x05;
			parse->temp_1[1] = 0xf6;
			parse->temp_1[2] = 0;
			parse->temp_1[3] = 0;
			parse->temp_cmd = parse->temp_1;
			parse->state = ASS_ST_UNKNOWN;
			return (1);
		case 0xf7:		/* system exclusive end */
			switch (parse->state) {
			case ASS_ST_SYSEX_0:
				parse->temp_1[0] = p0 | 0x05;
				parse->temp_1[1] = 0xf7;
				parse->temp_1[2] = 0;
				parse->temp_1[3] = 0;
				parse->temp_cmd = parse->temp_1;
				parse->state = ASS_ST_UNKNOWN;
				return (2);
			case ASS_ST_SYSEX_1:
				parse->temp_1[0] = p0 | 0x06;
				parse->temp_1[2] = 0xf7;
				parse->temp_1[3] = 0;
				parse->temp_cmd = parse->temp_1;
				parse->state = ASS_ST_UNKNOWN;
				return (2);
			case ASS_ST_SYSEX_2:
				parse->temp_1[0] = p0 | 0x07;
				parse->temp_1[3] = 0xf7;
				parse->temp_cmd = parse->temp_1;
				parse->state = ASS_ST_UNKNOWN;
				return (2);
			}
			parse->state = ASS_ST_UNKNOWN;
			break;
		}
	} else if (b >= 0x80) {
		parse->temp_1[1] = b;
		if ((b >= 0xc0) && (b <= 0xdf)) {
			parse->state = ASS_ST_1PARAM;
		} else {
			parse->state = ASS_ST_2PARAM_1;
		}
	} else {			/* b < 0x80 */
		switch (parse->state) {
		case ASS_ST_1PARAM:
			if (parse->temp_1[1] < 0xf0) {
				p0 |= parse->temp_1[1] >> 4;
			} else {
				p0 |= 0x02;
				parse->state = ASS_ST_UNKNOWN;
			}
			parse->temp_1[0] = p0;
			parse->temp_1[2] = b;
			parse->temp_1[3] = 0;
			parse->temp_cmd = parse->temp_1;
			return (1);
		case ASS_ST_2PARAM_1:
			parse->temp_1[2] = b;
			parse->state = ASS_ST_2PARAM_2;
			break;
		case ASS_ST_2PARAM_2:
			if (parse->temp_1[1] < 0xf0) {
				p0 |= parse->temp_1[1] >> 4;
				parse->state = ASS_ST_2PARAM_1;
			} else {
				p0 |= 0x03;
				parse->state = ASS_ST_UNKNOWN;
			}
			parse->temp_1[0] = p0;
			parse->temp_1[3] = b;
			parse->temp_cmd = parse->temp_1;
			return (1);
		case ASS_ST_SYSEX_0:
			parse->temp_1[1] = b;
			parse->state = ASS_ST_SYSEX_1;
			break;
		case ASS_ST_SYSEX_1:
			parse->temp_1[2] = b;
			parse->state = ASS_ST_SYSEX_2;
			break;
		case ASS_ST_SYSEX_2:
			parse->temp_1[0] = p0 | 0x04;
			parse->temp_1[3] = b;
			parse->temp_cmd = parse->temp_1;
			parse->state = ASS_ST_SYSEX_0;
			return (2);
		default:
			break;
		}
	}
	return (0);
}

static	bool
ass_fifo_empty(struct ass_fifo *fifo)
{
	return (fifo->producer == fifo->consumer);
}

#if 0
static	bool
ass_fifo_full(struct ass_fifo *fifo)
{
	unsigned size = fifo->producer - fifo->consumer;

	if (size >= ASS_FIFO_MAX)
		return (true);
	return (false);
}
#endif

static bool
ass_fifo_push(struct ass_fifo *fifo, struct snd_seq_event *event)
{
	unsigned size = fifo->producer - fifo->consumer;

	if (size >= ASS_FIFO_MAX)
		return (false);
	fifo->data[fifo->producer++ % ASS_FIFO_MAX] = *event;
	ass_wakeup();
	return (true);
}

static	bool
ass_fifo_pull(struct ass_fifo *fifo, struct snd_seq_event *event)
{
	unsigned size = fifo->producer - fifo->consumer;

	if (size == 0)
		return (false);
	*event = fifo->data[fifo->consumer++ % ASS_FIFO_MAX];
	return (true);
}

static struct ass_client *
ass_client_by_number(int number)
{
	struct ass_client *pass;

	TAILQ_FOREACH(pass, &ass_client_head, entry) {
		if (pass->number == number)
			break;
	}
	return (pass);
}

static struct ass_port *
ass_port_by_number(struct ass_client *pass, int number)
{
	struct ass_port *port;

	TAILQ_FOREACH(port, &pass->head, entry) {
		if (port->addr.port == number)
			break;
	}
	return (port);
}

static struct ass_client *
ass_get_event_dest_client(struct snd_seq_event *event, int filter)
{
	struct ass_client *dest;

	dest = ass_client_by_number(event->dest.client);
	if (dest == NULL)
		return (NULL);
	if (!dest->accept_input)
		return (NULL);
	if ((dest->filter & SNDRV_SEQ_FILTER_USE_EVENT) &&
	    (dest->event_filter[event->type / 8] & (1 << (event->type % 8))) == 0)
		return (NULL);
	if (filter && !(dest->filter & filter))
		return (NULL);
	return (dest);
}

static bool
ass_send_synth_event(struct snd_seq_event *ev, int fd)
{
	uint8_t buffer[3] = {};
	int len;

	switch (ev->type) {
	case SNDRV_SEQ_EVENT_NOTEON:
		buffer[0] |= 0x90;
		break;
	case SNDRV_SEQ_EVENT_NOTEOFF:
		buffer[0] |= 0x80;
		break;
	case SNDRV_SEQ_EVENT_KEYPRESS:
		buffer[0] |= 0xA0;
		break;
	case SNDRV_SEQ_EVENT_CONTROLLER:
		buffer[0] |= 0xB0;
		break;
	case SNDRV_SEQ_EVENT_PGMCHANGE:
		buffer[0] |= 0xC0;
		break;
	case SNDRV_SEQ_EVENT_CHANPRESS:
		buffer[0] |= 0xD0;
		break;
	case SNDRV_SEQ_EVENT_PITCHBEND:
		buffer[0] |= 0xE0;
		break;
	case SNDRV_SEQ_EVENT_SYSEX:
		return (write(fd, &ev->data.ext.ptr, ev->data.ext.len) == ev->data.ext.len);
	case SNDRV_SEQ_EVENT_QFRAME:
		buffer[0] |= 0xF1;
		break;
	case SNDRV_SEQ_EVENT_SONGPOS:
		buffer[0] |= 0xF2;
		break;
	case SNDRV_SEQ_EVENT_SONGSEL:
		buffer[0] |= 0xF3;
		break;
	case SNDRV_SEQ_EVENT_TUNE_REQUEST:
		buffer[0] |= 0xF6;
		break;
	case SNDRV_SEQ_EVENT_CLOCK:
		buffer[0] |= 0xF8;
		break;
	case SNDRV_SEQ_EVENT_START:
		buffer[0] |= 0xFA;
		break;
	case SNDRV_SEQ_EVENT_CONTINUE:
		buffer[0] |= 0xFB;
		break;
	case SNDRV_SEQ_EVENT_STOP:
		buffer[0] |= 0xFC;
		break;
	case SNDRV_SEQ_EVENT_SENSING:
		buffer[0] |= 0xFE;
		break;
	case SNDRV_SEQ_EVENT_RESET:
		buffer[0] |= 0xFF;
		break;
	default:
		return (true);
	}

	switch (ev->type) {
	case SNDRV_SEQ_EVENT_NOTEON:
	case SNDRV_SEQ_EVENT_NOTEOFF:
	case SNDRV_SEQ_EVENT_KEYPRESS:
		buffer[0] |= ev->data.note.channel & 0xF;
		buffer[1] |= ev->data.note.note & 0x7F;
		buffer[2] |= ev->data.note.velocity & 0x7F;
		len = 3;
		break;
	case SNDRV_SEQ_EVENT_CHANPRESS:
	case SNDRV_SEQ_EVENT_PGMCHANGE:
		buffer[0] |= ev->data.control.channel & 0xF;
		buffer[1] |= ev->data.control.value & 0x7F;
		len = 2;
		break;
	case SNDRV_SEQ_EVENT_CONTROLLER:
		buffer[0] |= ev->data.control.channel & 0xF;
		buffer[1] |= ev->data.control.param & 0x7F;
		buffer[2] |= ev->data.control.value & 0x7F;
		len = 3;
		break;
	case SNDRV_SEQ_EVENT_PITCHBEND:
		buffer[0] |= ev->data.control.channel & 0xF;
		buffer[1] |= (ev->data.control.value + 8192) & 0x7F;
		buffer[2] |= ((ev->data.control.value + 8192) >> 7) & 0x7F;
		len = 3;
		break;
	case SNDRV_SEQ_EVENT_QFRAME:
	case SNDRV_SEQ_EVENT_SONGSEL:
		buffer[1] |= ev->data.control.value & 0x7F;
		len = 2;
		break;
	case SNDRV_SEQ_EVENT_SONGPOS:
		buffer[1] |= (ev->data.control.value & 0x7F);
		buffer[2] |= ((ev->data.control.value >> 7) & 0x7F);
		len = 3;
		break;
	default:
		len = 1;
		break;
	}
	return (write(fd, buffer, len) == len);
}

static bool
ass_receive_synth_event(struct snd_seq_event *ev,
    struct ass_parse *parse, int fd)
{
	uint8_t buffer[1];

	while (read(fd, buffer, sizeof(buffer)) == 1) {
		switch (ass_midi_convert(parse, 0, buffer[0])) {
		case 0:
			continue;
		case 1:
			break;
		default:
			memset(ev, 0, sizeof(*ev));
			ev->type = SNDRV_SEQ_EVENT_SYSEX;
			ev->flags = SNDRV_SEQ_EVENT_LENGTH_VARIABLE;
			ev->data.ext.len = ass_cmd_to_len[parse->temp_cmd[0] & 0xF];
			/* internal hack */ 
			memcpy(&ev->data.ext.ptr, parse->temp_cmd + 1, ev->data.ext.len);
			return (true);
		}

		memset(ev, 0, sizeof(*ev));
		switch ((parse->temp_cmd[1] & 0xF0) >> 4) {
		case 0x9:
			ev->type = SNDRV_SEQ_EVENT_NOTEON;
			break;
		case 0x8:
			ev->type = SNDRV_SEQ_EVENT_NOTEOFF;
			break;
		case 0xA:
			ev->type = SNDRV_SEQ_EVENT_KEYPRESS;
			break;
		case 0xB:
			ev->type = SNDRV_SEQ_EVENT_CONTROLLER;
			break;
		case 0xC:
			ev->type = SNDRV_SEQ_EVENT_PGMCHANGE;
			break;
		case 0xD:
			ev->type = SNDRV_SEQ_EVENT_CHANPRESS;
			break;
		case 0xE:
			ev->type = SNDRV_SEQ_EVENT_PITCHBEND;
			break;
		case 0xF:
			switch (parse->temp_cmd[1] & 0x0F) {
			case 0x1:
				ev->type = SNDRV_SEQ_EVENT_QFRAME;
				break;
			case 0x2:
				ev->type = SNDRV_SEQ_EVENT_SONGPOS;
				break;
			case 0x3:
				ev->type = SNDRV_SEQ_EVENT_SONGSEL;
				break;
			case 0x6:
				ev->type = SNDRV_SEQ_EVENT_TUNE_REQUEST;
				break;
			case 0x8:
				ev->type = SNDRV_SEQ_EVENT_CLOCK;
				break;
			case 0xA:
				ev->type = SNDRV_SEQ_EVENT_START;
				break;
			case 0xB:
				ev->type = SNDRV_SEQ_EVENT_CONTINUE;
				break;
			case 0xC:
				ev->type = SNDRV_SEQ_EVENT_STOP;
				break;
			case 0xE:
				ev->type = SNDRV_SEQ_EVENT_SENSING;
				break;
			case 0xF:
				ev->type = SNDRV_SEQ_EVENT_RESET;
				break;
			default:
				continue;
			}
			break;
		default:
			continue;
		}

		switch (ev->type) {
		case SNDRV_SEQ_EVENT_NOTEON:
		case SNDRV_SEQ_EVENT_NOTEOFF:
		case SNDRV_SEQ_EVENT_KEYPRESS:
			ev->data.note.channel = parse->temp_cmd[1] & 0xF;
			ev->data.note.note = parse->temp_cmd[2] & 0x7F;
			ev->data.note.velocity = parse->temp_cmd[3] & 0x7F;
			break;
		case SNDRV_SEQ_EVENT_PGMCHANGE:
		case SNDRV_SEQ_EVENT_CHANPRESS:
			ev->data.control.channel = parse->temp_cmd[1] & 0xF;
			ev->data.control.value = parse->temp_cmd[2] & 0x7F;
			break;
		case SNDRV_SEQ_EVENT_CONTROLLER:
			ev->data.control.channel = parse->temp_cmd[1] & 0xF;
			ev->data.control.param = parse->temp_cmd[2] & 0x7F;
			ev->data.control.value = parse->temp_cmd[3] & 0x7F;
			break;
		case SNDRV_SEQ_EVENT_PITCHBEND:
			ev->data.control.channel = parse->temp_cmd[1] & 0xF;
			ev->data.control.value =
			    (parse->temp_cmd[2] & 0x7F) |
			    ((parse->temp_cmd[3] & 0x7F) << 7);
			ev->data.control.value -= 8192;
			break;
		case SNDRV_SEQ_EVENT_QFRAME:
		case SNDRV_SEQ_EVENT_SONGSEL:
			ev->data.control.value = parse->temp_cmd[1] & 0x7F;
			break;
		case SNDRV_SEQ_EVENT_SONGPOS:
			ev->data.control.value = (parse->temp_cmd[1] & 0x7F) |
			    ((parse->temp_cmd[2] & 0x7F) << 7);
			break;
		default:
			break;
		}
		return (true);
	}
	return (false);
}

static int
ass_check_port_perm(struct ass_port *port, unsigned int flags)
{
	if ((port->capability & flags) != flags)
		return (0);
	return (flags);
}

static void
ass_deliver_single_event(struct ass_client *client,
    struct snd_seq_event *event, int filter)
{
	struct ass_client *dest;
	struct ass_port *dest_port;

	dest = ass_get_event_dest_client(event, filter);
	if (dest == NULL)
		return;
	dest_port = ass_port_by_number(dest, event->dest.port);
	if (dest_port == NULL)
		return;
	if (!ass_check_port_perm(dest_port, SNDRV_SEQ_PORT_CAP_WRITE))
		return;

	switch (dest->type) {
	case USER_CLIENT:
		if (!ass_fifo_push(&dest->rx_fifo, event))
			client->event_lost++;
		break;
	case KERNEL_CLIENT:
		if (dest->tx_fd > -1 &&
		    !ass_send_synth_event(event, dest->tx_fd))
			client->event_lost++;
		break;
	default:
		break;
	}
}

static void
ass_deliver_to_subscribers(struct ass_client *client,
    struct snd_seq_event *event)
{
	struct ass_subscribers *subs;
	struct ass_port *src_port;

	src_port = ass_port_by_number(client, event->source.port);
	if (src_port == NULL)
		return;

	TAILQ_FOREACH(subs, &src_port->c_src.head, src_entry) {
		if (subs->ref_count != 2)
			continue;
		event->dest = subs->info.dest;
		ass_deliver_single_event(client, event, 0);
	}
}

static int
ass_read(struct cuse_dev *pdev, int fflags, void *peer_ptr, int len)
{
	struct ass_client *pass;
	struct snd_seq_event temp[2];
	int error;
	int retval;

	pass = cuse_dev_get_per_file_handle(pdev);
	if (pass == NULL)
		return (CUSE_ERR_INVALID);

	ass_lock();
	if (pass->rx_busy) {
		ass_unlock();
		return (CUSE_ERR_BUSY);
	}
	retval = 0;

	while (len >= (int)sizeof(temp)) {
		int delta;

		if (ass_fifo_pull(&pass->rx_fifo, &temp[0]) == false) {
			/* out of data */
			if (fflags & CUSE_FFLAG_NONBLOCK) {
				if (retval == 0)
					retval = CUSE_ERR_WOULDBLOCK;
				break;
			}
			/* check if we got some data */
			if (retval != 0)
				break;
			pass->rx_busy = 1;
			ass_wait();
			pass->rx_busy = 0;
			if (cuse_got_peer_signal() == 0) {
				retval = CUSE_ERR_SIGNAL;
				break;
			}
			continue;
		}

		if ((temp[0].flags & SNDRV_SEQ_EVENT_LENGTH_MASK) == SNDRV_SEQ_EVENT_LENGTH_VARIABLE) {
			/* copy data in-place */
			memcpy(&temp[1], &temp[0].data.ext.ptr, sizeof(temp[0].data.ext.ptr));
			temp[0].data.ext.ptr = NULL;
			delta = sizeof(temp);
		} else {
			delta = sizeof(temp[0]);
		}

		pass->rx_busy = 1;
		ass_unlock();
		error = cuse_copy_out(&temp[0], peer_ptr, delta);
		ass_lock();
		pass->rx_busy = 0;

		if (error != 0) {
			retval = error;
			break;
		}
		peer_ptr = (uint8_t *)peer_ptr + delta;
		retval += delta;
		len -= delta;
	}
	ass_unlock();

	return (retval);
}

static int
ass_write(struct cuse_dev *pdev, int fflags, const void *peer_ptr, int len)
{
	struct ass_client *pass;
	struct snd_seq_event temp;
	uint8_t var_data[ASS_FIFO_MAX * sizeof(void *)];
	int error;
	int retval;

	pass = cuse_dev_get_per_file_handle(pdev);
	if (pass == NULL)
		return (CUSE_ERR_INVALID);

	retval = 0;

	ass_lock();
	if (pass->tx_busy) {
		ass_unlock();
		return (CUSE_ERR_BUSY);
	}
	while (len >= (int)sizeof(temp)) {
		int delta;

		pass->tx_busy = 1;
		ass_unlock();
		error = cuse_copy_in(peer_ptr, &temp, sizeof(temp));
		ass_lock();
		pass->tx_busy = 0;

		if (error != 0) {
			retval = error;
			break;
		}

		temp.source.client = pass->number;

		if ((temp.flags & SNDRV_SEQ_EVENT_LENGTH_MASK) ==
		    SNDRV_SEQ_EVENT_LENGTH_VARIABLE) {
			temp.data.ext.len &= ~0xc0000000U;

			delta = temp.data.ext.len + sizeof(temp);
			if (delta < (int)sizeof(temp) ||
			    delta > len ||
			    delta > (int)(sizeof(temp) + sizeof(var_data))) {
				retval = CUSE_ERR_INVALID;
				break;
			}

			if (temp.type == SNDRV_SEQ_EVENT_SYSEX) {
				int off;

				pass->tx_busy = 1;
				ass_unlock();
				error = cuse_copy_in((const uint8_t *)peer_ptr +
				    sizeof(temp), var_data, delta - sizeof(temp));
				ass_lock();
				pass->tx_busy = 0;

				if (error != 0) {
					retval = error;
					break;
				}

				/* split up and deliver the event(s) */
				for (off = 0; off < (int)(delta - sizeof(temp)); off += sizeof(temp.data.ext.ptr)) {
					int x = delta - sizeof(temp) - off;
					if (x > (int)sizeof(temp.data.ext.ptr))
						x = sizeof(temp.data.ext.ptr);
					temp.data.ext.len = x;
					memcpy(&temp.data.ext.ptr, var_data + off, x);
					ass_deliver_to_subscribers(pass, &temp);
				}
			}
		} else {
			delta = sizeof(temp);

			/* check if event should be delivered */
			if (temp.type != SNDRV_SEQ_EVENT_NONE &&
			    temp.type != SNDRV_SEQ_EVENT_SYSEX &&
			    temp.type != SNDRV_SEQ_EVENT_BOUNCE)
				ass_deliver_to_subscribers(pass, &temp);
		}

		peer_ptr = (const uint8_t *)peer_ptr + delta;
		retval += delta;
		len -= delta;
	}
	ass_unlock();

	return (retval);
}

static struct ass_port *
ass_create_port(struct ass_client *pass, int addr)
{
	struct ass_port *port;
	struct ass_port *pother;
	bool loop;

	if (pass->num_ports >= ASS_MAX_PORTS ||
	    addr >= ASS_MAX_PORTS)
		return (NULL);

	port = malloc(sizeof(*port));
	if (port == NULL)
		return (NULL);

	memset(port, 0, sizeof(*port));

	port->addr.client = pass->number;

	if (addr < 0) {
		do {
			loop = false;
			TAILQ_FOREACH(pother, &pass->head, entry) {
				if (pother->addr.port == port->addr.port) {
					port->addr.port++;
					loop = true;
				}
			}
		} while (loop);
	} else {
		if (ass_port_by_number(pass, addr) != NULL) {
			free(port);
			return (NULL);
		}
		port->addr.port = addr;
	}
	TAILQ_INIT(&port->c_dst.head);
	TAILQ_INIT(&port->c_src.head);
	pass->num_ports++;
	snprintf(port->name, sizeof(port->name), "port-%d", port->addr.port);
	TAILQ_INSERT_TAIL(&pass->head, port, entry);
	return (port);
}

static int
ass_set_port_info(struct ass_port *port, struct snd_seq_port_info *info)
{
	if (info->name[0])
		strlcpy(port->name, info->name, sizeof(port->name));
	port->capability = info->capability;
	port->type = info->type;
	port->midi_channels = info->midi_channels;
	port->midi_voices = info->midi_voices;
	port->synth_voices = info->synth_voices;
	port->timestamping = (info->flags & SNDRV_SEQ_PORT_FLG_TIMESTAMP) ? 1 : 0;
	port->time_real = (info->flags & SNDRV_SEQ_PORT_FLG_TIME_REAL) ? 1 : 0;
	port->time_queue = info->time_queue;
	return (0);
}

static int
ass_get_port_info(struct ass_port *port, struct snd_seq_port_info *info)
{
	strlcpy(info->name, port->name, sizeof(info->name));
	info->capability = port->capability;
	info->type = port->type;
	info->midi_channels = port->midi_channels;
	info->midi_voices = port->midi_voices;
	info->synth_voices = port->synth_voices;
	info->read_use = port->c_src.count;
	info->write_use = port->c_dst.count;
	info->flags = 0;
	if (port->timestamping) {
		info->flags |= SNDRV_SEQ_PORT_FLG_TIMESTAMP;
		if (port->time_real)
			info->flags |= SNDRV_SEQ_PORT_FLG_TIME_REAL;
		info->time_queue = port->time_queue;
	}
	return (0);
}

static	bool
ass_addr_match(struct snd_seq_addr *r, struct snd_seq_addr *s)
{
	return (r->client == s->client && r->port == s->port);
}

static int
ass_match_subs_info(struct snd_seq_port_subscribe *r,
    struct snd_seq_port_subscribe *s)
{
	if (ass_addr_match(&r->sender, &s->sender) &&
	    ass_addr_match(&r->dest, &s->dest)) {
		if (r->flags && r->flags == s->flags)
			return (r->queue == s->queue);
		else if (!r->flags)
			return (1);
	}
	return (0);
}

static int
ass_port_get_subscription(struct ass_port_subs_info *src_grp,
    struct snd_seq_addr *dest_addr,
    struct snd_seq_port_subscribe *subs)
{
	struct ass_subscribers *s;

	TAILQ_FOREACH(s, &src_grp->head, src_entry) {
		if (ass_addr_match(dest_addr, &s->info.dest)) {
			*subs = s->info;
			return (0);
		}
	}
	return (CUSE_ERR_NO_DEVICE);
}

#define	PERM_RD		(SNDRV_SEQ_PORT_CAP_READ|SNDRV_SEQ_PORT_CAP_SUBS_READ)
#define	PERM_WR		(SNDRV_SEQ_PORT_CAP_WRITE|SNDRV_SEQ_PORT_CAP_SUBS_WRITE)

static int
ass_check_subscription_permission(struct ass_client *client,
    struct ass_port *sport, struct ass_port *dport,
    struct snd_seq_port_subscribe *subs)
{
	if (client->number != subs->sender.client &&
	    client->number != subs->dest.client) {
		if (ass_check_port_perm(sport, SNDRV_SEQ_PORT_CAP_NO_EXPORT))
			return (CUSE_ERR_INVALID);
		if (ass_check_port_perm(dport, SNDRV_SEQ_PORT_CAP_NO_EXPORT))
			return (CUSE_ERR_INVALID);
	}
	if (client->number != subs->sender.client) {
		if (!ass_check_port_perm(sport, PERM_RD))
			return (CUSE_ERR_INVALID);
	}
	if (client->number != subs->dest.client) {
		if (!ass_check_port_perm(dport, PERM_WR))
			return (CUSE_ERR_INVALID);
	}
	return (0);
}

static void
ass_client_notify_subscription(struct ass_client *client,
    int dst_client, int dst_port,
    struct snd_seq_port_subscribe *info, int evtype)
{
	struct snd_seq_event event;

	memset(&event, 0, sizeof(event));
	event.type = evtype;
	event.flags = SNDRV_SEQ_EVENT_LENGTH_FIXED;
	event.source.client = -1;
	event.source.port = -1;
	event.dest.client = dst_client;
	event.dest.port = dst_port;
	event.data.connect.dest = info->dest;
	event.data.connect.sender = info->sender;

	ass_deliver_single_event(client, &event, 0);
}

static int
ass_subscribe_port(struct ass_client *client,
    struct ass_port *port,
    struct ass_port_subs_info *grp,
    struct snd_seq_port_subscribe *info,
    int send_ack)
{
	/* check if kernel device is ready before allowing subscribe */
	if (client->type == KERNEL_CLIENT) {
		if (grp == &port->c_src && client->rx_fd < 0)
			return (CUSE_ERR_INVALID);
		if (grp == &port->c_dst && client->tx_fd < 0)
			return (CUSE_ERR_INVALID);
	}

	grp->count++;

	if (send_ack && client->type == USER_CLIENT) {
		ass_client_notify_subscription(client, port->addr.client, port->addr.port,
		    info, SNDRV_SEQ_EVENT_PORT_SUBSCRIBED);
	}
	return (0);
}

static int
ass_unsubscribe_port(struct ass_client *client,
    struct ass_port *port,
    struct ass_port_subs_info *grp,
    struct snd_seq_port_subscribe *info,
    int send_ack)
{

	if (grp->count == 0)
		return (CUSE_ERR_INVALID);
	grp->count--;

	if (send_ack && client->type == USER_CLIENT) {
		ass_client_notify_subscription(client, port->addr.client, port->addr.port,
		    info, SNDRV_SEQ_EVENT_PORT_UNSUBSCRIBED);
	}
	return (0);
}

static int
ass_check_and_subscribe_port(struct ass_client *client,
    struct ass_port *port, struct ass_subscribers *subs,
    bool is_src, bool exclusive, bool ack)
{
	struct ass_port_subs_info *grp;
	struct ass_subscribers *s;
	int err = CUSE_ERR_BUSY;

	grp = is_src ? &port->c_src : &port->c_dst;

	if (exclusive) {
		if (!TAILQ_EMPTY(&grp->head))
			return (err);
	} else {
		if (grp->exclusive)
			return (err);

		if (is_src) {
			TAILQ_FOREACH(s, &grp->head, src_entry) {
				if (ass_match_subs_info(&subs->info, &s->info))
					return (err);
			}
		} else {
			TAILQ_FOREACH(s, &grp->head, dst_entry) {
				if (ass_match_subs_info(&subs->info, &s->info))
					return (err);
			}
		}
	}

	err = ass_subscribe_port(client, port, grp, &subs->info, ack);
	if (err != 0) {
		grp->exclusive = 0;
		return (err);
	}
	if (is_src)
		TAILQ_INSERT_TAIL(&grp->head, subs, src_entry);
	else
		TAILQ_INSERT_TAIL(&grp->head, subs, dst_entry);

	grp->exclusive = exclusive;
	subs->ref_count++;
	return (0);
}

static void
ass_delete_and_unsubscribe_port(struct ass_client *client,
    struct ass_port *port,
    struct ass_subscribers *subs,
    bool is_src, bool ack)
{
	struct ass_subscribers *s;

	if (is_src) {
		TAILQ_FOREACH(s, &port->c_src.head, src_entry) {
			if (s != subs)
				continue;
			TAILQ_REMOVE(&port->c_src.head, s, src_entry);
			ass_unsubscribe_port(client, port, &port->c_src, &subs->info, ack);
			break;
		}
	} else {
		TAILQ_FOREACH(s, &port->c_dst.head, dst_entry) {
			if (s != subs)
				continue;
			TAILQ_REMOVE(&port->c_dst.head, s, dst_entry);
			ass_unsubscribe_port(client, port, &port->c_dst, &subs->info, ack);
			break;
		}
	}
}

static void
ass_clear_subscriber_list(struct ass_client *client,
    struct ass_port *port,
    struct ass_port_subs_info *grp,
    int is_src)
{
	struct ass_subscribers *subs;
	struct ass_subscribers *temp;
	struct ass_client *c;
	struct ass_port *aport;

	if (is_src) {
		TAILQ_FOREACH_SAFE(subs, &port->c_src.head, src_entry, temp) {
			ass_delete_and_unsubscribe_port(client, port, subs, is_src, false);
			if ((c = ass_client_by_number(subs->info.dest.client)) != NULL &&
			    (aport = ass_port_by_number(c, subs->info.dest.port)) != NULL) {
				ass_delete_and_unsubscribe_port(c, aport, subs, !is_src, true);
				free(subs);
			} else {
				if (--subs->ref_count == 0)
					free(subs);
			}
		}
	} else {
		TAILQ_FOREACH_SAFE(subs, &port->c_dst.head, dst_entry, temp) {
			ass_delete_and_unsubscribe_port(client, port, subs, is_src, false);
			if ((c = ass_client_by_number(subs->info.sender.client)) != NULL &&
			    (aport = ass_port_by_number(c, subs->info.sender.port)) != NULL) {
				ass_delete_and_unsubscribe_port(c, aport, subs, !is_src, true);
				free(subs);
			} else {
				if (--subs->ref_count == 0)
					free(subs);
			}
		}
	}
}

static void
ass_delete_port(struct ass_client *client, struct ass_port *port)
{
	ass_clear_subscriber_list(client, port, &port->c_src, true);
	ass_clear_subscriber_list(client, port, &port->c_dst, false);

	assert(port->c_src.count == 0);
	assert(port->c_dst.count == 0);

	TAILQ_REMOVE(&client->head, port, entry);
	client->num_ports--;

	free(port);
}

static int
ass_port_connect(struct ass_client *connector,
    struct ass_client *src_client,
    struct ass_port *src_port,
    struct ass_client *dest_client,
    struct ass_port *dest_port,
    struct snd_seq_port_subscribe *info)
{
	struct ass_subscribers *subs;
	bool exclusive;
	int err;

	subs = malloc(sizeof(*subs));
	if (subs == NULL)
		return (CUSE_ERR_NO_MEMORY);
	memset(subs, 0, sizeof(*subs));

	subs->info = *info;

	exclusive = !!(info->flags & SNDRV_SEQ_PORT_SUBS_EXCLUSIVE);

	err = ass_check_and_subscribe_port(src_client, src_port, subs, true,
	    exclusive, connector->number != src_client->number);
	if (err != 0)
		goto err_0;
	err = ass_check_and_subscribe_port(dest_client, dest_port, subs, false,
	    exclusive, connector->number != dest_client->number);
	if (err != 0)
		goto err_1;

	return (0);
err_1:
	ass_delete_and_unsubscribe_port(src_client, src_port, subs, true,
	    connector->number != src_client->number);
err_0:
	free(subs);
	return (err);
}

static int
ass_port_disconnect(struct ass_client *connector,
    struct ass_client *src_client,
    struct ass_port *src_port,
    struct ass_client *dest_client,
    struct ass_port *dest_port,
    struct snd_seq_port_subscribe *info)
{
	struct ass_subscribers *subs;

	TAILQ_FOREACH(subs, &src_port->c_src.head, src_entry) {
		if (ass_match_subs_info(info, &subs->info))
			break;
	}
	if (subs == NULL)
		return (CUSE_ERR_NO_DEVICE);
	subs->ref_count--;

	ass_delete_and_unsubscribe_port(src_client, src_port, subs, true,
	    connector->number != src_client->number);
	ass_delete_and_unsubscribe_port(dest_client, dest_port, subs, false,
	    connector->number != dest_client->number);
	free(subs);
	return (0);
}

static void
ass_get_client_info(struct ass_client *client,
    struct snd_seq_client_info *info)
{
	info->client = client->number;
	info->type = client->type;
	strlcpy(info->name, client->name, sizeof(info->name));
	info->filter = client->filter;
	info->event_lost = client->event_lost;
	memcpy(info->event_filter, client->event_filter, 32);
	info->num_ports = client->num_ports;
	info->pid = -1;
	info->card = -1;
}

static int
ass_ioctl(struct cuse_dev *pdev, int fflags, unsigned long cmd, void *peer_data)
{
	struct ass_client *pass;
	struct ass_client *receiver;
	struct ass_client *sender;
	struct ass_client *pother;
	struct ass_port *port;
	struct ass_port *dport;
	struct ass_port *sport;
	struct ass_subscribers *s;
	int i;
	int len;
	int error = 0;

	union {
		struct snd_seq_system_info sinfo;
		struct snd_seq_client_info cinfo;
		struct snd_seq_port_info pinfo;
		struct snd_seq_port_subscribe psubs;
		struct snd_seq_query_subs qsubs;
		struct snd_seq_queue_status qstatus;
		struct snd_seq_queue_tempo qtempo;
		struct snd_seq_queue_timer qtimer;
		struct snd_seq_queue_client qclient;
		struct snd_seq_queue_info qinfo;
		struct snd_seq_remove_events remev;
		struct snd_seq_client_pool cpool;
		struct snd_seq_running_info rinfo;
		int	value;
	}     data;

	pass = cuse_dev_get_per_file_handle(pdev);
	if (pass == NULL)
		return (CUSE_ERR_INVALID);

	len = IOCPARM_LEN(cmd);

	if (len < 0 || len > (int)sizeof(data))
		return (CUSE_ERR_INVALID);

	if (cmd & IOC_IN) {
		error = cuse_copy_in(peer_data, &data, len);
		if (error)
			return (error);
	} else {
		/* clear reply buffer */
		memset(&data, 0, len);
		error = 0;
	}

	ass_lock();

	switch (cmd) {
	case FIOASYNC:
	case FIONBIO:
		break;
	case SNDRV_SEQ_IOCTL_PVERSION:
		data.value = SNDRV_PROTOCOL_VERSION(1, 0, 2);
		break;
	case SNDRV_SEQ_IOCTL_CLIENT_ID:
		data.value = pass->number;
		break;
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
		error = CUSE_ERR_NO_DEVICE;
		while (1) {
			if (data.cinfo.client == ASS_MAX_CLIENTS - 1)
				break;
			if (data.cinfo.client < 0 || data.cinfo.client >= ASS_MAX_CLIENTS)
				data.cinfo.client = 0;
			else
				data.cinfo.client++;
			pother = ass_client_by_number(data.cinfo.client);
			if (pother != NULL) {
				/* Skip listing disconnected clients. */
				if (pother->type == KERNEL_CLIENT &&
				    pother->rx_fd < 0 &&
				    pother->tx_fd < 0)
					continue;

				ass_get_client_info(pother, &data.cinfo);
				error = 0;
				break;
			}
		}
		break;
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT:
		error = CUSE_ERR_NO_DEVICE;
		pother = ass_client_by_number(data.pinfo.addr.client);
		if (pother == NULL)
			break;
		while (1) {
			if (data.pinfo.addr.port == ASS_MAX_PORTS - 1)
				break;
			if (data.pinfo.addr.port >= ASS_MAX_PORTS)
				data.pinfo.addr.port = 0;
			else
				data.pinfo.addr.port++;
			port = ass_port_by_number(pother, data.pinfo.addr.port);
			if (port != NULL) {
				data.pinfo.addr = port->addr;
				ass_get_port_info(port, &data.pinfo);
				error = 0;
				break;
			}
		}
		break;
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
		data.sinfo.queues = ASS_MAX_QUEUES;
		data.sinfo.clients = ASS_MAX_CLIENTS;
		data.sinfo.ports = ASS_MAX_PORTS;
		data.sinfo.channels = 256;
		TAILQ_FOREACH(pother, &ass_client_head, entry)
		    data.sinfo.cur_clients++;
		data.sinfo.cur_queues = 0;
		break;
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
		pother = ass_client_by_number(data.rinfo.client);
		if (pother == NULL) {
			error = CUSE_ERR_NO_DEVICE;
			break;
		}
		ass_get_client_info(pother, &data.cinfo);
		break;
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
		if (pass->number != data.cinfo.client ||
		    pass->type != data.cinfo.type) {
			error = CUSE_ERR_INVALID;
			break;
		}
		if (data.cinfo.name[0])
			strlcpy(pass->name, data.cinfo.name, sizeof(pass->name));

		pass->filter = data.cinfo.filter;
		pass->event_lost = data.cinfo.event_lost;
		memcpy(pass->event_filter, data.cinfo.event_filter, 32);
		break;
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
		if (pass->number != data.pinfo.addr.client ||
		    data.pinfo.kernel != 0) {
			error = CUSE_ERR_INVALID;
			break;
		}
		port = ass_create_port(pass, (data.pinfo.flags &
		    SNDRV_SEQ_PORT_FLG_GIVEN_PORT) ? data.pinfo.addr.port : -1);
		if (port == NULL) {
			error = CUSE_ERR_NO_MEMORY;
			break;
		}
		data.pinfo.addr = port->addr;
		ass_set_port_info(port, &data.pinfo);
		break;
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
		if (pass->number != data.pinfo.addr.client) {
			error = CUSE_ERR_INVALID;
			break;
		}
		TAILQ_FOREACH(port, &pass->head, entry) {
			if (port->addr.port == data.pinfo.addr.port)
				break;
		}
		if (port == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		ass_delete_port(pass, port);
		break;
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
		pother = ass_client_by_number(data.pinfo.addr.client);
		if (pother == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		port = ass_port_by_number(pother, data.pinfo.addr.port);
		if (port == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		ass_get_port_info(port, &data.pinfo);
		break;
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
		if (pass->number != data.pinfo.addr.client) {
			error = CUSE_ERR_INVALID;
			break;
		}
		port = ass_port_by_number(pass, data.pinfo.addr.port);
		if (port == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		ass_set_port_info(port, &data.pinfo);
		break;
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
		pother = ass_client_by_number(data.psubs.sender.client);
		if (pother == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		port = ass_port_by_number(pother, data.psubs.sender.port);
		if (port == NULL) {
			error = CUSE_ERR_INVALID;
			break;
		}
		error = ass_port_get_subscription(&port->c_src, &data.psubs.dest, &data.psubs);
		break;
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
		if ((receiver = ass_client_by_number(data.psubs.dest.client)) == NULL ||
		    (sender = ass_client_by_number(data.psubs.sender.client)) == NULL ||
		    (sport = ass_port_by_number(sender, data.psubs.sender.port)) == NULL ||
		    (dport = ass_port_by_number(receiver, data.psubs.dest.port)) == NULL) {
			error = CUSE_ERR_NO_DEVICE;
			break;
		}
		error = ass_check_subscription_permission(pass, sport, dport, &data.psubs);
		if (error)
			break;
		error = ass_port_connect(pass, sender, sport, receiver, dport, &data.psubs);
		break;
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
		if ((receiver = ass_client_by_number(data.psubs.dest.client)) == NULL ||
		    (sender = ass_client_by_number(data.psubs.sender.client)) == NULL ||
		    (sport = ass_port_by_number(sender, data.psubs.sender.port)) == NULL ||
		    (dport = ass_port_by_number(receiver, data.psubs.dest.port)) == NULL) {
			error = CUSE_ERR_NO_DEVICE;
			break;
		}
		error = ass_check_subscription_permission(pass, sport, dport, &data.psubs);
		if (error)
			break;
		error = ass_port_disconnect(pass, sender, sport, receiver, dport, &data.psubs);
		break;
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
		if ((pother = ass_client_by_number(data.qsubs.root.client)) == NULL ||
		    (port = ass_port_by_number(pother, data.qsubs.root.port)) == NULL) {
			error = CUSE_ERR_NO_DEVICE;
			break;
		}
		switch (data.qsubs.type) {
		case SNDRV_SEQ_QUERY_SUBS_READ:
			i = 0;
			data.qsubs.num_subs = port->c_src.count;
			TAILQ_FOREACH(s, &port->c_src.head, src_entry) {
				if (i++ == data.qsubs.index) {
					data.qsubs.addr = s->info.dest;
					data.qsubs.flags = s->info.flags;
					data.qsubs.queue = s->info.queue;
					break;
				}
			}
			break;
		case SNDRV_SEQ_QUERY_SUBS_WRITE:
			i = 0;
			data.qsubs.num_subs = port->c_dst.count;
			TAILQ_FOREACH(s, &port->c_dst.head, dst_entry) {
				if (i++ == data.qsubs.index) {
					data.qsubs.addr = s->info.sender;
					data.qsubs.flags = s->info.flags;
					data.qsubs.queue = s->info.queue;
					break;
				}
			}
			break;
		default:
			s = NULL;
			break;
		}
		if (s == NULL)
			error = CUSE_ERR_NO_DEVICE;
		break;
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
		error = CUSE_ERR_INVALID;
		break;
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
		pother = ass_client_by_number(data.rinfo.client);
		if (pother == NULL) {
			error = CUSE_ERR_NO_DEVICE;
			break;
		}
#ifdef SNDRV_BIG_ENDIAN
		if (!data.rinfo.big_endian) {
			error = CUSE_ERR_INVALID;
			break;
		}
#else
		if (data.rinfo.big_endian) {
			error = CUSE_ERR_INVALID;
			break;
		}
#endif
		if (data.rinfo.cpu_mode > sizeof(long)) {
			error = CUSE_ERR_INVALID;
			break;
		}
		pother->convert32 = (data.rinfo.cpu_mode < sizeof(long));
		break;
	default:
		error = CUSE_ERR_INVALID;
		break;
	}
	ass_unlock();

	if (error == 0) {
		if (cmd & IOC_OUT)
			error = cuse_copy_out(&data, peer_data, len);
	}
	return (error);
}

static int
ass_open(struct cuse_dev *pdev, int fflags)
{
	struct ass_client *pass;
	struct ass_client *pother;
	bool loop;

	pass = malloc(sizeof(*pass));
	if (pass == NULL)
		return (CUSE_ERR_NO_MEMORY);

	memset(pass, 0, sizeof(*pass));

	cuse_dev_set_per_file_handle(pdev, pass);

	ass_lock();
	do {
		loop = false;
		TAILQ_FOREACH(pother, &ass_client_head, entry) {
			if (pother->number == pass->number) {
				pass->number++;
				loop = true;
			}
		}
	} while (loop);

	if (pass->number >= ASS_MAX_CLIENTS) {
		ass_unlock();
		free(pass);
		return (CUSE_ERR_NO_MEMORY);
	}
	pass->type = USER_CLIENT;
	if (fflags & FREAD)
		pass->accept_input = 1;
	if (fflags & FWRITE)
		pass->accept_output = 1;
	TAILQ_INIT(&pass->head);
	snprintf(pass->name, sizeof(pass->name), "Client-%d", pass->number);
	TAILQ_INSERT_TAIL(&ass_client_head, pass, entry);
	ass_wakeup();
	ass_unlock();

	return (0);
}

static int
ass_close(struct cuse_dev *pdev, int fflags)
{
	struct ass_client *pass;
	struct ass_port *port;

	pass = cuse_dev_get_per_file_handle(pdev);
	if (pass == NULL)
		return (CUSE_ERR_INVALID);

	ass_lock();
	while ((port = TAILQ_FIRST(&pass->head)))
		ass_delete_port(pass, port);
	TAILQ_REMOVE(&ass_client_head, pass, entry);
	ass_unlock();

	free(pass);

	return (0);
}

static int
ass_poll(struct cuse_dev *pdev, int fflags, int events)
{
	struct ass_client *pass;

	int retval = CUSE_POLL_NONE;

	pass = cuse_dev_get_per_file_handle(pdev);
	if (pass == NULL)
		return (retval);

	ass_lock();
	if (events & CUSE_POLL_READ) {
		if (pass->accept_input) {
			if (!ass_fifo_empty(&pass->rx_fifo))
				retval |= CUSE_POLL_READ;
		}
	}
	if (events & CUSE_POLL_WRITE) {
		if (pass->accept_output) {
			retval |= CUSE_POLL_WRITE;
		}
	}
	ass_unlock();

	return (retval);
}

struct ass_client *
ass_create_kernel_client(unsigned int caps, char *rx_name, char *tx_name)
{
	struct ass_client *pass;
	struct ass_client *pother;
	struct ass_port *port;
	bool loop;

	pass = malloc(sizeof(*pass));
	if (pass == NULL)
		return (NULL);

	memset(pass, 0, sizeof(*pass));

	ass_lock();
	do {
		loop = false;
		TAILQ_FOREACH(pother, &ass_client_head, entry) {
			if (pother->number == pass->number) {
				pass->number++;
				loop = true;
			}
		}
	} while (loop);

	if (pass->number >= ASS_MAX_CLIENTS) {
		ass_unlock();
		free(pass);
		return (NULL);
	}
	pass->type = KERNEL_CLIENT;
	TAILQ_INIT(&pass->head);
	pass->rx_fd = -1;
	pass->tx_fd = -1;
	pass->rx_name = rx_name;
	pass->tx_name = tx_name;
	snprintf(pass->name, sizeof(pass->name), "Client-%d", pass->number);
	port = ass_create_port(pass, 0);
	if (port == NULL) {
		ass_unlock();
		free(pass);
		return (NULL);
	}
	if (caps & SNDRV_SEQ_PORT_CAP_WRITE)
		pass->accept_input = 1;
	if (caps & SNDRV_SEQ_PORT_CAP_READ)
		pass->accept_output = 1;
	port->capability = caps;
	port->type = SNDRV_SEQ_PORT_TYPE_MIDI_GENERIC;
	port->midi_channels = 16;
	TAILQ_INSERT_TAIL(&ass_client_head, pass, entry);
	ass_wakeup();
	ass_unlock();
	return (pass);
}

static void
ass_watchdog_sub(struct ass_client *pass)
{
	int fd;
	bool any = false;
	struct ass_port *port;

	if (pass->rx_name == NULL) {
		/* do nothing */
	} else if (pass->rx_fd < 0) {
		fd = open(pass->rx_name, O_RDONLY | O_NONBLOCK);
		if (fd > -1) {
			pass->rx_fd = fd;
			fcntl(pass->rx_fd, F_SETFL, (int)O_NONBLOCK);
			any = true;
			ass_wakeup();
		}
	} else {
		if (fcntl(pass->rx_fd, F_SETFL, (int)O_NONBLOCK) == -1) {
			DPRINTF("Close read\n");
			close(pass->rx_fd);
			pass->rx_fd = -1;
			TAILQ_FOREACH(port, &pass->head, entry)
				ass_clear_subscriber_list(pass, port, &port->c_src, true);
		}
	}

	if (pass->tx_name == NULL) {
		/* do nothing */
	} else if (pass->tx_fd < 0) {
		fd = open(pass->tx_name, O_WRONLY | O_NONBLOCK);
		if (fd > -1) {
			pass->tx_fd = fd;
			fcntl(pass->tx_fd, F_SETFL, (int)0);
			any = true;
			ass_wakeup();
		}
	} else {
		if (fcntl(pass->tx_fd, F_SETFL, (int)0) == -1) {
			DPRINTF("Close write\n");
			close(pass->tx_fd);
			pass->tx_fd = -1;
			TAILQ_FOREACH(port, &pass->head, entry)
				ass_clear_subscriber_list(pass, port, &port->c_dst, false);
		}
	}

	if (any) {
		int unit = -1;
		int subunit = 0;
		const char *pname = NULL;

		if (pass->rx_name != NULL) {
			if (strncmp(pass->rx_name, "/dev/", 5) == 0) {
				pname = pass->rx_name + 5;
				sscanf(pass->rx_name, "/dev/umidi%d.%d", &unit, &subunit);
			} else {
				pname = pass->rx_name;
			}
		} else {
			if (strncmp(pass->tx_name, "/dev/", 5) == 0) {
				pname = pass->tx_name + 5;
				sscanf(pass->tx_name, "/dev/umidi%d.%d", &unit, &subunit);
			} else {
				pname = pass->tx_name;
			}
		}

		if (unit > -1) {
			size_t size = sizeof(pass->name);

			/* create sysctl name */
			snprintf(pass->name, sizeof(pass->name), "dev.uaudio.%d.%%desc", unit);

			/* lookup sysctl */
			if (sysctlbyname(pass->name, pass->name, &size, NULL, 0) == 0 ||
			    (errno == ENOMEM)) {
				char *ptr;

				/* check string length */
				if (size > sizeof(pass->name) - 1)
					size = sizeof(pass->name) - 1;

				/* zero terminate */
				pass->name[size] = 0;

				/* split */
				ptr = strchr(pass->name, ',');
				if (ptr != NULL) {
					size = ptr - pass->name;
					*ptr = 0;
				}
				/* limit the string length */
				if (strlen(pass->name) > 16) {
					pass->name[16] = 0;
					size = 16;
				}
			} else {
				strlcpy(pass->name, pname, sizeof(pass->name));
			}
		} else {
			strlcpy(pass->name, pname, sizeof(pass->name));
		}

		/* store port number */
		port = TAILQ_FIRST(&pass->head);
		if (port != NULL)
			snprintf(port->name, sizeof(port->name), "port-%d", subunit);
	}
}

static void *
ass_watchdog(void *arg)
{
	struct ass_client *pass;

	while (1) {
		ass_lock();
		TAILQ_FOREACH(pass, &ass_client_head, entry) {
			if (pass->type == KERNEL_CLIENT)
				ass_watchdog_sub(pass);
		}
		ass_unlock();
		usleep(1000000);
	}
}

static void *
ass_midi_process(void *arg)
{
	struct ass_client *pass;
	struct pollfd pfd[ASS_MAX_CLIENTS] = {};
	struct snd_seq_event temp;
	int n;

	ass_lock();
	while (1) {
		n = 0;
		TAILQ_FOREACH(pass, &ass_client_head, entry) {
			if (pass->type != KERNEL_CLIENT ||
			    pass->rx_fd < 0 ||
			    n == ASS_MAX_CLIENTS)
				continue;
			pfd[n].fd = pass->rx_fd;
			pfd[n].events = POLLIN | POLLRDNORM;
			pfd[n].revents = 0;
			n++;
		}
		if (n == 0) {
			ass_wait();
			continue;
		}
		ass_unlock();

		poll(pfd, n, -1);

		ass_lock();
		n = 0;
		TAILQ_FOREACH(pass, &ass_client_head, entry) {
			if (pass->type != KERNEL_CLIENT ||
			    pass->rx_fd < 0 ||
			    n == ASS_MAX_CLIENTS)
				continue;
			if (pfd[n].revents & POLLIN) {
				while (ass_receive_synth_event(&temp, &pass->parse, pass->rx_fd)) {
					temp.source.client = pass->number;
					ass_deliver_to_subscribers(pass, &temp);
				}
			}
			n++;
		}
	}
	ass_unlock();
}

static void
usage(void)
{
	fprintf(stderr,
	    "alsa-seq-server - RAW USB/socket to ALSA SEQ server\n"
	    "	-F /dev/umidi (install capture and playback filter)\n"
	    "	-d /dev/umidi0.0 (add capture and playback device)\n"
	    "	-C /dev/umidi0.0 (add capture only device)\n"
	    "	-P /dev/umidi0.0 (add playback only device)\n"
	    "	-U <username> (set this username for sequencer device, default is 0)\n"
	    "	-G <groupname> (set this groupname for sequencer device, default is 0)\n"
	    "	-m <mode> (set this permission mode for sequencer device, default is 0666)\n"
	    "	-s <devicename> (set sequencer device name, default is snd/seq)\n"
	    "	-B (run in background)\n"
	    "	-h (show help)\n");
	exit(0);
}

static void
ass_pipe(int dummy)
{

}

static void
ass_hup(int sig)
{
	ass_wakeup();
}

static void *
ass_cuse_process(void *arg)
{
	while (1) {
		if (cuse_wait_and_process() != 0)
			break;
	}
	return (NULL);
}

static void
ass_create_cuse_threads(void)
{
	pthread_t td;
	int idx;

	for (idx = 0; idx != ASS_MAX_CLIENTS; idx++)
		pthread_create(&td, NULL, &ass_cuse_process, NULL);

	pthread_create(&td, NULL, &ass_midi_process, NULL);

	autodetect_init();
}

static const struct cuse_methods ass_methods = {
	.cm_open = ass_open,
	.cm_close = ass_close,
	.cm_read = ass_read,
	.cm_write = ass_write,
	.cm_ioctl = ass_ioctl,
	.cm_poll = ass_poll,
};

int
main(int argc, char **argv)
{
	struct ass_client *pass;
	int c;

	while ((c = getopt(argc, argv, "d:F:C:P:U:G:m:s:Bh")) != -1) {
		switch (c) {
		case 'F':
			autodetect_filter_add(optarg);
			break;
		case 'B':
			background = true;
			break;
		case 'd':
			pass = ass_create_kernel_client(
			    SNDRV_SEQ_PORT_CAP_WRITE |
			    SNDRV_SEQ_PORT_CAP_READ |
			    SNDRV_SEQ_PORT_CAP_SYNC_READ |
			    SNDRV_SEQ_PORT_CAP_SYNC_WRITE |
			    SNDRV_SEQ_PORT_CAP_DUPLEX |
			    SNDRV_SEQ_PORT_CAP_SUBS_READ |
			    SNDRV_SEQ_PORT_CAP_SUBS_WRITE,
			    optarg, optarg);
			if (pass == NULL)
				usage();
			break;
		case 'P':
			pass = ass_create_kernel_client(
			    SNDRV_SEQ_PORT_CAP_WRITE |
			    SNDRV_SEQ_PORT_CAP_SYNC_WRITE |
			    SNDRV_SEQ_PORT_CAP_SUBS_WRITE,
			    NULL, optarg);
			if (pass == NULL)
				usage();
			break;
		case 'C':
			pass = ass_create_kernel_client(
			    SNDRV_SEQ_PORT_CAP_READ |
			    SNDRV_SEQ_PORT_CAP_SYNC_READ |
			    SNDRV_SEQ_PORT_CAP_SUBS_READ,
			    optarg, NULL);
			if (pass == NULL)
				usage();
			break;
		case 'U':
			ass_uid(optarg);
			break;
		case 'G':
			ass_gid(optarg);
			break;
		case 'm':
			mode = strtol(optarg, NULL, 8);
			break;
		case 's':
			dname = optarg;
			break;
		default:
			usage();
		}
	}

	if (background) {
		if (daemon(0, 0))
			errx(EX_UNAVAILABLE, "Could not become daemon");
	}

	signal(SIGPIPE, ass_pipe);
	signal(SIGHUP, ass_hup);

	ass_init();

	if (cuse_init() != 0)
		errx(EX_USAGE, "Could not connect to cuse module");

	if (cuse_dev_create(&ass_methods, NULL, NULL, uid, gid, mode, "%s", dname) == NULL)
		errx(EX_USAGE, "Could not create '/dev/%s'", dname);

	ass_create_cuse_threads();

	ass_watchdog(NULL);

	return (0);
}
