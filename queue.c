/*-
 * Copyright (c) 2022 Hans Petter Selasky <hselasky@FreeBSD.org>
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
 * Based on ALSA sequencer Timing queue handling
 * Copyright (c) 1998-1999 by Frank van de Pol <fvdpol@coil.demon.nl>
 */

#include "alsa-seq-server.h"

#include <cuse.h>

static struct ass_queue ass_queue[ASS_MAX_QUEUES];
static pthread_cond_t ass_queue_cv;
static struct snd_seq_real_time ass_queue_time_low;
static uint32_t ass_queue_time_high;
static bool ass_queue_time_busy;

#define	ASS_QUEUE_FOREACH(pq) \
    for (pq = &ass_queue[0]; pq != &ass_queue[ASS_MAX_QUEUES]; pq++)

static void
ass_queue_wakeup(void)
{
	pthread_cond_broadcast(&ass_queue_cv);
}

static void
ass_queue_wait(void)
{
	pthread_cond_wait(&ass_queue_cv, &ass_mtx);
}

static int
ass_queue_timedwait(struct timespec *ts)
{
	return (pthread_cond_timedwait(&ass_queue_cv, &ass_mtx, ts));
}

static void
ass_queue_lock(void)
{
	pthread_mutex_lock(&ass_mtx);
}

static void
ass_queue_unlock(void)
{
	pthread_mutex_unlock(&ass_mtx);
}

static void
ass_queue_update_time(void)
{
	struct timespec ts;

	if (ass_queue_time_busy)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if ((uint32_t)ts.tv_sec < (uint32_t)ass_queue_time_low.tv_sec)
		ass_queue_time_high++;

	ass_queue_time_low.tv_sec = ts.tv_sec;
	ass_queue_time_low.tv_nsec = ts.tv_nsec;
}

#define	ASS_TO_NSEC(low, high)				\
  ((uint64_t)(high) * (1000000000ULL << 32) +		\
   (uint64_t)(uint32_t)(low).tv_sec * 1000000000ULL +	\
   (uint64_t)(low).tv_nsec)

static void
ass_queue_update_real_time_and_ticks(struct ass_queue *pq)
{
	uint64_t nsecs;

	/* timing is not easy ... */

	nsecs = ASS_TO_NSEC(ass_queue_time_low, ass_queue_time_high) -
	    ASS_TO_NSEC(pq->last_time_low, pq->last_time_high);
	pq->last_time_high = ass_queue_time_high;
	pq->last_time_low = ass_queue_time_low;

	pq->cur_time.tv_nsec += nsecs % 1000000000ULL;
	pq->cur_time.tv_sec += nsecs / 1000000000ULL;

	if (pq->cur_time.tv_nsec >= 1000000000) {
		pq->cur_time.tv_nsec -= 1000000000;
		pq->cur_time.tv_sec += 1;
	}

	nsecs += pq->ns_rem;
	pq->cur_tick += nsecs / pq->ns_tick;
	pq->ns_rem = nsecs % pq->ns_tick;
}

static void
ass_queue_sub_time(const struct snd_seq_real_time *pa, const struct snd_seq_real_time *pb,
    struct snd_seq_real_time *pc)
{
	pc->tv_nsec = pa->tv_nsec - pb->tv_nsec;
	pc->tv_sec = pa->tv_sec - pb->tv_sec;

	if ((int)pc->tv_nsec < 0) {
		pc->tv_nsec += 1000000000;
		pc->tv_sec -= 1;
	}
}

static void
ass_queue_add_time(const struct snd_seq_real_time *pa, const struct snd_seq_real_time *pb,
    struct snd_seq_real_time *pc)
{
	pc->tv_nsec = pa->tv_nsec + pb->tv_nsec;
	pc->tv_sec = pa->tv_sec + pb->tv_sec;

	if ((int)pc->tv_nsec >= 1000000000) {
		pc->tv_nsec -= 1000000000;
		pc->tv_sec += 1;
	}
}

static void
ass_queue_free_event(struct ass_event *event)
{
	struct ass_client *pass;

	pass = ass_client_by_number(event->event.source.client);
	if (pass != NULL && pass->output_used != 0)
		pass->output_used--;
	free(event);
}

static void *
ass_queue_watchdog(void *arg)
{
	struct ass_queue *pq;
	struct ass_event *pev;
	struct ass_client *pass;
	struct snd_seq_real_time time_real;
	struct timespec abstime;
	int time_tick;
	uint64_t next_event;
	uint64_t temp;

	ass_queue_lock();

	for (;;) {

		ass_queue_update_time();
		ass_queue_time_busy = true;

		next_event = -1ULL;

		ASS_QUEUE_FOREACH(pq) {
			if (pq->allocated == 0 || pq->running == 0)
				continue;
			ass_queue_update_real_time_and_ticks(pq);
	head_real_loop:
			pev = TAILQ_FIRST(&pq->head_real);
			if (pev != NULL) {
				ass_queue_sub_time(&pev->event.time.time, &pq->cur_time, &time_real);
				if ((int)time_real.tv_sec < 0 ||
				    (time_real.tv_sec == 0 && time_real.tv_nsec == 0)) {
					TAILQ_REMOVE(&pq->head_real, pev, entry);
					pass = ass_client_by_number(pev->event.source.client);
					if (pass != NULL)
						ass_deliver_to_subscribers(pass, &pev->event);
					pq->events--;
					ass_queue_free_event(pev);
					goto head_real_loop;
				} else {
					temp = (uint64_t)(uint32_t)time_real.tv_sec * 1000000000ULL +
					    (uint64_t)time_real.tv_nsec;
					if (temp < next_event)
						next_event = temp;
				}
			}
	head_tick_loop:
			pev = TAILQ_FIRST(&pq->head_tick);
			if (pev != NULL) {
				time_tick = pev->event.time.tick - pq->cur_tick;
				if (time_tick <= 0) {
					TAILQ_REMOVE(&pq->head_tick, pev, entry);
					pass = ass_client_by_number(pev->event.source.client);
					if (pass != NULL)
						ass_deliver_to_subscribers(pass, &pev->event);
					pq->events--;
					ass_queue_free_event(pev);
					goto head_tick_loop;
				} else {
					temp = (uint64_t)time_tick * pq->ns_tick - pq->ns_rem;
					if (temp < next_event)
						next_event = temp;
				}
			}
		}

		ass_queue_time_busy = false;

		if (next_event == -1ULL) {
			ass_queue_wait();
		} else {
			next_event += 1;	/* make sure event has passed */
			abstime.tv_sec = ass_queue_time_low.tv_sec;
			abstime.tv_nsec = ass_queue_time_low.tv_nsec;
			abstime.tv_sec += next_event / 1000000000ULL;
			abstime.tv_nsec += next_event % 1000000000ULL;
			if (abstime.tv_nsec >= 1000000000) {
				abstime.tv_nsec -= 1000000000;
				abstime.tv_sec += 1;
			}
			ass_queue_timedwait(&abstime);
		}
	}
	ass_queue_unlock();
	return (NULL);
}

void
ass_queue_init(void)
{
	pthread_t td;
	pthread_condattr_t attr;
	struct ass_queue *pq;

	ASS_QUEUE_FOREACH(pq) {
		TAILQ_INIT(&pq->head_real);
		TAILQ_INIT(&pq->head_tick);
	}

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&ass_queue_cv, &attr);
	pthread_condattr_destroy(&attr);

	ass_queue_update_time();

	pthread_create(&td, NULL, &ass_queue_watchdog, NULL);
}

static void
ass_queue_timer_update(struct ass_queue *pq)
{
	pq->ns_tick =
	    ((uint64_t)pq->tempo * 1000ULL * (uint64_t)pq->skew_base) /
	    ((uint64_t)pq->ppq * (uint64_t)pq->skew_value);
}

static void
ass_queue_timer_defaults(struct ass_queue *pq)
{
	pq->running = 0;
	pq->skew_value = pq->skew_base = 0x10000;
	pq->tempo = 500000;
	pq->ppq = 96;
	pq->resolution = 1000;
	ass_queue_timer_update(pq);
}

static void
ass_queue_timer_event_start_common(struct ass_queue *pq)
{
	ass_queue_update_time();
	pq->last_time_low = ass_queue_time_low;
	pq->last_time_high = ass_queue_time_high;
	pq->running = 1;
	pq->ns_rem = 0;
	pq->cur_time.tv_sec = 0;
	pq->cur_time.tv_nsec = 0;
	pq->cur_tick = 0;
	ass_queue_wakeup();
}

static struct ass_queue * ass_queue_by_index(unsigned);
static bool ass_check_access(struct ass_queue *, int client);

static void
ass_queue_timer_event_start(int client, int queue)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;
	ass_queue_timer_event_start_common(pq);
}

static void
ass_queue_timer_event_continue(int client, int queue)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;
	ass_queue_update_time();
	pq->last_time_low = ass_queue_time_low;
	pq->last_time_high = ass_queue_time_high;
	pq->running = 1;
	ass_queue_wakeup();
}

static void
ass_queue_timer_event_stop(int client, int queue)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;
	pq->running = 0;
}

static void
ass_queue_timer_event_tempo(int client, int queue, int value)
{
	struct ass_queue *pq;

	if (value <= 0)
		return;
	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;
	pq->tempo = value;
	ass_queue_timer_update(pq);
}

static void
ass_queue_timer_event_setpos_tick(int client, int queue, snd_seq_tick_time_t tick)
{
	struct ass_queue *pq;
	uint64_t nsecs;

	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;

	nsecs = (uint64_t)(uint32_t)tick * pq->ns_tick;
	pq->cur_time.tv_sec = nsecs / 1000000000ULL;
	pq->cur_time.tv_nsec = nsecs % 1000000000ULL;
	pq->cur_tick = tick;
	pq->ns_rem = 0;
	ass_queue_wakeup();
}

static void
ass_queue_timer_event_setpos_time(int client, int queue, struct snd_seq_real_time time)
{
	struct ass_queue *pq;
	uint64_t nsecs;

	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;

	nsecs = (uint64_t)(uint32_t)time.tv_sec * 1000000000ULL + (uint64_t)time.tv_nsec;
	pq->cur_time = time;
	pq->cur_tick = nsecs / pq->ns_tick;
	pq->ns_rem = nsecs % pq->ns_tick;
	ass_queue_wakeup();
}

static void
ass_queue_timer_event_set_skew(int client, int queue, int value, int base)
{
	struct ass_queue *pq;

	if (value <= 0 || base <= 0)
		return;
	pq = ass_queue_by_index(queue);
	if (pq == NULL)
		return;
	if (ass_check_access(pq, client) == false)
		return;
	pq->skew_value = value;
	pq->skew_base = base;
	ass_queue_timer_update(pq);
}

void
ass_queue_filter_events(const struct snd_seq_event *event)
{
	if (event->dest.client != SNDRV_SEQ_CLIENT_SYSTEM ||
	    event->dest.port != SNDRV_SEQ_PORT_SYSTEM_TIMER)
		return;

	switch (event->type) {
	case SNDRV_SEQ_EVENT_START:
		ass_queue_timer_event_start(event->source.client, event->data.queue.queue);
		break;

	case SNDRV_SEQ_EVENT_CONTINUE:
		ass_queue_timer_event_continue(event->source.client, event->data.queue.queue);
		break;

	case SNDRV_SEQ_EVENT_STOP:
		ass_queue_timer_event_stop(event->source.client, event->data.queue.queue);
		break;

	case SNDRV_SEQ_EVENT_TEMPO:
		ass_queue_timer_event_tempo(event->source.client, event->data.queue.queue,
		    event->data.queue.param.value);
		break;

	case SNDRV_SEQ_EVENT_SETPOS_TICK:
		ass_queue_timer_event_setpos_tick(event->source.client, event->data.queue.queue,
		    event->data.queue.param.time.tick);
		break;

	case SNDRV_SEQ_EVENT_SETPOS_TIME:
		ass_queue_timer_event_setpos_time(event->source.client, event->data.queue.queue,
		    event->data.queue.param.time.time);
		break;

	case SNDRV_SEQ_EVENT_QUEUE_SKEW:
		ass_queue_timer_event_set_skew(event->source.client, event->data.queue.queue,
		    event->data.queue.param.skew.value,
		    event->data.queue.param.skew.base);
		break;

	default:
		break;
	}
}

int
ass_queue_create(struct ass_client *client, struct snd_seq_queue_info *info)
{
	struct ass_queue *pq;

	ASS_QUEUE_FOREACH(pq) {
		if (pq->allocated)
			continue;
		pq->allocated = 1;
		pq->locked = info->locked ? true : false;
		pq->owner = client->number;
		pq->clients = 0;
		pq->clients_bitmap = 0;
		ass_queue_timer_defaults(pq);

		info->queue = pq - ass_queue;
		info->owner = client->number;

		if (!info->name[0])
			snprintf(info->name, sizeof(info->name), "Queue-%zu", pq - ass_queue);
		strlcpy(pq->name, info->name, sizeof(pq->name));

		return (0);
	}
	return (CUSE_ERR_NO_MEMORY);
}

static void
ass_queue_drain(ass_event_head_t *phead)
{
	struct ass_event *pev;

	while ((pev = TAILQ_FIRST(phead)) != NULL) {
		TAILQ_REMOVE(phead, pev, entry);
		ass_queue_free_event(pev);
	}
}

static struct ass_queue *
ass_queue_by_index(unsigned q)
{
	if (q >= ASS_MAX_QUEUES || ass_queue[q].allocated == 0)
		return (NULL);
	return (&ass_queue[q]);
}

static void
ass_queue_delete_common(struct ass_queue *pq)
{
	pq->allocated = 0;
	pq->events = 0;

	ass_queue_drain(&pq->head_real);
	ass_queue_drain(&pq->head_tick);
}

int
ass_queue_delete(struct ass_client *client, struct snd_seq_queue_info *info)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(info->queue);
	if (pq == NULL || pq->owner != client->number)
		return (CUSE_ERR_INVALID);

	ass_queue_delete_common(pq);
	return (0);
}

static struct ass_queue *
ass_queue_find_by_name(const char *name, size_t len)
{
	struct ass_queue *pq;

	ASS_QUEUE_FOREACH(pq) {
		if (pq->allocated == 0)
			continue;
		if (strncmp(pq->name, name, len) == 0)
			return (pq);
	}
	return (NULL);
}

static bool
ass_queue_event_is_gte_tick(const struct ass_event *pa, const struct ass_event *pb)
{
	int diff = pa->event.time.tick - pb->event.time.tick;

	return (diff >= 0);
}

static bool
ass_queue_event_is_gte_real(const struct ass_event *pa, const struct ass_event *pb)
{
	struct snd_seq_real_time diff;

	ass_queue_sub_time(&pa->event.time.time, &pb->event.time.time, &diff);
	return ((int)diff.tv_sec >= 0);
}

void
ass_queue_deliver_to_subscribers(struct ass_client *pass, const struct snd_seq_event *event)
{
	struct ass_event *pev;
	struct ass_event *pother;
	struct ass_queue *pq;

	pq = ass_queue_by_index(event->queue);
	if (pq == NULL)
		return;

	if (pass->output_used == ASS_FIFO_MAX)
		return;

	pev = malloc(sizeof(*pev));
	if (pev == NULL)
		return;

	pev->event = *event;
	pev->event.queue = SNDRV_SEQ_QUEUE_DIRECT;

	switch (pev->event.flags & SNDRV_SEQ_TIME_STAMP_MASK) {
	case SNDRV_SEQ_TIME_STAMP_TICK:
		if ((pev->event.flags & SNDRV_SEQ_TIME_MODE_MASK) == SNDRV_SEQ_TIME_MODE_REL)
			pev->event.time.tick += pq->cur_tick;

		/* absolute time */
		pev->event.flags &= ~SNDRV_SEQ_TIME_MODE_MASK;
		pev->event.flags |= SNDRV_SEQ_TIME_MODE_ABS;

		pq->events++;
		pass->output_used++;

		for (pother = TAILQ_LAST(&pq->head_tick, ass_event_head); pother != 0;
		    pother = TAILQ_PREV(pother, ass_event_head, entry)) {

			if (ass_queue_event_is_gte_tick(pev, pother)) {
				TAILQ_INSERT_AFTER(&pq->head_tick, pother, pev, entry);
				return;
			}
		}

		pother = TAILQ_FIRST(&pq->head_tick);
		if (pother == NULL || ass_queue_event_is_gte_tick(pev, pother) == false) {
			TAILQ_INSERT_HEAD(&pq->head_tick, pev, entry);
			ass_queue_wakeup();
		} else {
			TAILQ_INSERT_TAIL(&pq->head_tick, pev, entry);
		}
		return;

	case SNDRV_SEQ_TIME_STAMP_REAL:
		if ((pev->event.flags & SNDRV_SEQ_TIME_MODE_MASK) == SNDRV_SEQ_TIME_MODE_REL)
			ass_queue_add_time(&pev->event.time.time, &pq->cur_time, &pev->event.time.time);

		/* absolute time */
		pev->event.flags &= ~SNDRV_SEQ_TIME_MODE_MASK;
		pev->event.flags |= SNDRV_SEQ_TIME_MODE_ABS;

		pq->events++;
		pass->output_used++;

		for (pother = TAILQ_LAST(&pq->head_real, ass_event_head); pother != 0;
		    pother = TAILQ_PREV(pother, ass_event_head, entry)) {

			if (ass_queue_event_is_gte_real(pev, pother)) {
				TAILQ_INSERT_AFTER(&pq->head_real, pother, pev, entry);
				return;
			}
		}

		pother = TAILQ_FIRST(&pq->head_real);
		if (pother == NULL || ass_queue_event_is_gte_real(pev, pother) == false) {
			TAILQ_INSERT_HEAD(&pq->head_real, pev, entry);
			ass_queue_wakeup();
		} else {
			TAILQ_INSERT_TAIL(&pq->head_real, pev, entry);
		}
		return;

	default:
		free(pev);
		return;
	}
}

static bool
ass_check_access(struct ass_queue *q, int client)
{
	return (q->owner == client || q->locked == false);
}

static bool
ass_queue_set_owner(struct ass_queue *q, int client, bool locked)
{
	if (ass_check_access(q, client) == false)
		return (false);

	q->locked = locked;
	q->owner = client;
	return (true);
}

int
ass_queue_get_info(struct ass_client *client, struct snd_seq_queue_info *info)
{
	struct ass_queue *pq = ass_queue_by_index(info->queue);

	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	memset(info, 0, sizeof(*info));

	info->queue = pq - ass_queue;
	info->owner = pq->owner;
	info->locked = pq->locked;
	strlcpy(info->name, pq->name, sizeof(info->name));
	return (0);
}

static void
ass_queue_update_use(struct ass_queue *pq, unsigned client, bool use)
{
	const unsigned m = 1U << client;

	if (use) {
		if (!(m & pq->clients_bitmap)) {
			if (pq->clients++ == 0)
				ass_queue_timer_defaults(pq);
		}
		pq->clients_bitmap |= m;
	} else {
		if (m & pq->clients_bitmap)
			pq->clients--;
		pq->clients_bitmap &= ~m;
	}

	if (pq->clients != 0) {
		if (pq->running == 0)
			ass_queue_timer_event_start_common(pq);
	} else {
		pq->running = 0;
	}
}

int
ass_queue_set_info(struct ass_client *client, struct snd_seq_queue_info *info)
{
	struct ass_queue *pq;

	if (info->owner != client->number)
		return (CUSE_ERR_INVALID);

	pq = ass_queue_by_index(info->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	if (ass_queue_set_owner(pq, client->number, info->locked) == false)
		return (CUSE_ERR_OTHER);

	if (info->locked)
		ass_queue_update_use(pq, client->number, true);

	strlcpy(pq->name, info->name, sizeof(pq->name));
	return (0);
}

int
ass_queue_by_name(struct ass_client *client, struct snd_seq_queue_info *info)
{
	struct ass_queue *pq;

	pq = ass_queue_find_by_name(info->name,
	    ASS_MIN(sizeof(info->name), sizeof(ass_queue[0].name)));
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	info->queue = pq - ass_queue;
	info->owner = pq->owner;
	info->locked = pq->locked;
	return (0);
}

int
ass_queue_get_status(struct ass_client *client, struct snd_seq_queue_status *status)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(status->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	ass_queue_update_time();
	ass_queue_update_real_time_and_ticks(pq);

	memset(status, 0, sizeof(*status));
	status->queue = pq - ass_queue;
	status->events = pq->events;
	status->time = pq->cur_time;
	status->tick = pq->cur_tick;
	status->running = pq->running;
	status->flags = 0;
	return (0);
}

int
ass_queue_get_tempo(struct ass_client *client, struct snd_seq_queue_tempo *tempo)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(tempo->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	memset(tempo, 0, sizeof(*tempo));
	tempo->queue = pq - ass_queue;
	tempo->tempo = pq->tempo;
	tempo->ppq = pq->ppq;
	tempo->skew_value = pq->skew_value;
	tempo->skew_base = pq->skew_base;
	return (0);
}

int
ass_queue_set_tempo(struct ass_client *client, struct snd_seq_queue_tempo *tempo)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(tempo->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);
	if (ass_check_access(pq, client->number) == false)
		return (CUSE_ERR_OTHER);

	/*
	 * Don't allow division by zero, and force skew base to be
	 * power of two:
	 */
	if (tempo->tempo <= 0 || tempo->ppq <= 0 ||
	    (tempo->skew_base & (tempo->skew_base - 1)) != 0)
		return (CUSE_ERR_INVALID);

	pq->tempo = tempo->tempo;
	pq->ppq = tempo->ppq;

	if (tempo->skew_base > 0 && tempo->skew_value > 0) {
		pq->skew_base = tempo->skew_base;
		pq->skew_value = tempo->skew_value;
	}
	ass_queue_timer_update(pq);
	return (0);
}

int
ass_queue_get_timer(struct ass_client *client, struct snd_seq_queue_timer *timer)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(timer->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	memset(timer, 0, sizeof(*timer));
	timer->queue = pq - ass_queue;
	timer->type = SNDRV_SEQ_TIMER_ALSA;
	timer->u.alsa.resolution = pq->resolution;
	return (0);
}

int
ass_queue_set_timer(struct ass_client *client, struct snd_seq_queue_timer *timer)
{
	struct ass_queue *pq;

	if (timer->type != SNDRV_SEQ_TIMER_ALSA)
		return (CUSE_ERR_INVALID);

	pq = ass_queue_by_index(timer->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);
	if (ass_check_access(pq, client->number) == false)
		return (CUSE_ERR_OTHER);

	pq->resolution = timer->u.alsa.resolution;
	return (0);
}

int
ass_queue_get_client(struct ass_client *client, struct snd_seq_queue_client *info)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(info->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	memset(info, 0, sizeof(*info));
	info->queue = pq - ass_queue;
	info->used = (pq->clients_bitmap >> client->number) & 1;
	info->client = client->number;
	return (0);
}

int
ass_queue_set_client(struct ass_client *client, struct snd_seq_queue_client *info)
{
	struct ass_queue *pq;

	pq = ass_queue_by_index(info->queue);
	if (pq == NULL)
		return (CUSE_ERR_INVALID);

	if (info->used >= 0) {
		ass_queue_update_use(pq,
		    client->number, info->used ? true : false);
	}
	return (ass_queue_get_client(client, info));
}

void
ass_queue_cleanup(int client)
{
	struct ass_queue *pq;

	ASS_QUEUE_FOREACH(pq) {
		if (pq->allocated == 0)
			continue;
		if ((pq->clients_bitmap >> client) & 1)
			ass_queue_update_use(pq, client, false);
		if (pq->owner == client)
			ass_queue_delete_common(pq);
	}
}
