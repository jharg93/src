/* Public domain. */

#ifndef _LINUX_TIMEKEEPING_H
#define _LINUX_TIMEKEEPING_H

#define ktime_get_boottime()	ktime_get()
#define get_seconds()		gettime()

static inline time_t
ktime_get_real_seconds(void)
{
	return gettime();
}

static inline ktime_t
ktime_get_real(void)
{
	struct timespec ts;
	nanotime(&ts);
	return TIMESPEC_TO_NSEC(&ts);
}

static inline uint64_t
ktime_get_ns(void)
{
	return ktime_get();
}

#endif
