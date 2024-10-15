/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include "hl_memory.h"
#include "perftest_parameters.h"
#include "synapse_api.h"
#include "hlthunk.h"
#include "khash.h"

KHASH_MAP_INIT_INT64(uint64_t, uint64_t)

#define ACCEL_PAGE_SIZE 4096

struct hl_memory_ctx {
	struct memory_ctx base;
	char *device_bus_id;
	synDeviceId device_id;
	int device_fd;
    khash_t(uint64_t) * mem_table_device;
    pthread_mutex_t mem_table_device_lock;
};

static bool hl_is_gaudi(int fd)
{
        enum hlthunk_device_name device;

        device = hlthunk_get_device_name_from_fd(fd);
	if ((device == HLTHUNK_DEVICE_GAUDI) ||
                        (device == HLTHUNK_DEVICE_GAUDI_HL2000M))
                return true;

        return false;
}

int hl_memory_init(struct memory_ctx *ctx) {
	struct hl_memory_ctx *hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
    hl_ctx->device_fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, hl_ctx->device_bus_id);

    hl_ctx->mem_table_device = kh_init(uint64_t);
    if (!hl_ctx->mem_table_device) {
		return FAILURE;
	}

    if (pthread_mutex_init(&hl_ctx->mem_table_device_lock, NULL)) {
       return FAILURE;
    }

	return SUCCESS;
}

int hl_memory_destroy(struct memory_ctx *ctx) {
	struct hl_memory_ctx *hl_ctx = container_of(ctx, struct hl_memory_ctx, base);

    kh_destroy(uint64_t, hl_ctx->mem_table_device);
    pthread_mutex_destroy(&hl_ctx->mem_table_device_lock);
    hlthunk_close(hl_ctx->device_fd);

	free(hl_ctx);
	return SUCCESS;
}

int hl_memory_allocate_buffer(struct memory_ctx *ctx, int alignment, uint64_t size, int *dmabuf_fd,
			      uint64_t *dmabuf_offset, void **addr, bool *can_init) {
	struct hl_memory_ctx *hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
	int fd;
	uint64_t buffer_addr;
	size_t buf_size = (size + ACCEL_PAGE_SIZE - 1) & ~(ACCEL_PAGE_SIZE - 1);

    int rc;
    khint_t k;
    uint64_t device_handle = hlthunk_device_memory_alloc(hl_ctx->device_fd, buf_size, 0, HL_MEM_CONTIGUOUS, false);
    if (!device_handle) {
        printf("Failed to allocate %lu bytes of device memory\n", buf_size);
        return FAILURE;
    }
    buffer_addr = hlthunk_device_memory_map(hl_ctx->device_fd, device_handle, 0);
    if (!buffer_addr) {
        printf("Failed to map device memory allocation\n");
        return FAILURE;
    }
    pthread_mutex_lock(&hl_ctx->mem_table_device_lock);
    k = kh_put(uint64_t, hl_ctx->mem_table_device, buffer_addr, &rc);
    kh_val(hl_ctx->mem_table_device, k) = device_handle;
    pthread_mutex_unlock(&hl_ctx->mem_table_device_lock);
    if (hl_is_gaudi(hl_ctx->device_fd)) {
        fd = hlthunk_device_memory_export_dmabuf_fd(hl_ctx->device_fd, buffer_addr, buf_size, 0);
    } else {
        fd = hlthunk_device_mapped_memory_export_dmabuf_fd(hl_ctx->device_fd, buffer_addr, buf_size, 0,
                                                                O_RDWR | O_CLOEXEC);
    }

	if (fd < 0) {
		fprintf(stderr, "Failed to export dmabuf. sz[%lu] ptr[%p] err[%d]\n",
			(unsigned long)buf_size, (void*)buffer_addr, fd);
		return FAILURE;
	}

	printf("Allocated %lu bytes of accelerator buffer at %p on fd %d\n",
	       (unsigned long)buf_size, (void*)buffer_addr, fd);
	*dmabuf_fd = fd;
	*dmabuf_offset = 0;
	*addr = (void*)buffer_addr;
	*can_init = false;
	return SUCCESS;
}

int hl_memory_free_buffer(struct memory_ctx *ctx, int dmabuf_fd, void *addr, uint64_t size) {
	struct hl_memory_ctx *hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
    khint_t k;
    int rc = hlthunk_memory_unmap(hl_ctx->device_fd, (void *)addr);

    if (rc) {
        printf("Failed to unmap host memory\n");
        return rc;
    }
    pthread_mutex_lock(&hl_ctx->mem_table_device_lock);
    k = kh_get(uint64_t, hl_ctx->mem_table_device, (uintptr_t) addr);
    if (k != kh_end(hl_ctx->mem_table_device)) {
        uint64_t device_handle = kh_val(hl_ctx->mem_table_device, k);
        hlthunk_device_memory_free(hl_ctx->device_fd, device_handle);
        kh_del(uint64_t, hl_ctx->mem_table_device, k);
    }
    pthread_mutex_unlock(&hl_ctx->mem_table_device_lock);
	return SUCCESS;
}

bool hl_memory_supported() {
	return true;
}

struct memory_ctx *hl_memory_create(struct perftest_parameters *params) {
	struct hl_memory_ctx *ctx;

	ALLOCATE(ctx, struct hl_memory_ctx, 1);
	ctx->base.init = hl_memory_init;
	ctx->base.destroy = hl_memory_destroy;
	ctx->base.allocate_buffer = hl_memory_allocate_buffer;
	ctx->base.free_buffer = hl_memory_free_buffer;
	ctx->base.copy_host_to_buffer = memcpy;
	ctx->base.copy_buffer_to_host = memcpy;
	ctx->base.copy_buffer_to_buffer = memcpy;
	ctx->device_bus_id = params->hl_device_bus_id;
	return &ctx->base;
}
