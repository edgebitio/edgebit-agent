#ifndef MAPS_H
#define MAPS_H

/*
#define BPF_ARRAY(name, val_type, size) \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __uint(max_entries, size); \
        __type(key, u32); \
        __type(value, val_type); \
    } name SEC("maps")

#define BPF_HASH(name, key_type, val_type, size) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, size); \
        __type(key, key_type); \
        __type(value, val_type); \
    } name SEC("maps")

#define BPF_RING_BUF(name, size) \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, size); \
    } name SEC("maps")

#define BPF_PERF_EVENT_ARRAY(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
        __uint(key_size, sizeof(u32)); \
        __uint(value_size, sizeof(u32)); \
    } name SEC("maps")
*/

#define BPF_PERF_EVENT_ARRAY(name) \
	struct bpf_map_def SEC("maps") name = { \
		.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
		.key_size = sizeof(int), \
		.value_size = sizeof(u32), \
		.max_entries = 1024, \
	}

#endif
