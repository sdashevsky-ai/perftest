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

#define ACCEL_PAGE_SIZE (4096)
#define INVALID_FD (-1)

struct hl_memory_ctx {
    struct memory_ctx base;
    char *device_bus_id;
    synDeviceId device_id;
    int device_fd;
    khash_t(uint64_t) *mem_handle_table;
    pthread_mutex_t mem_handle_table_lock;
};

static bool hl_is_gaudi1(const int fd) {
    const enum hlthunk_device_name device = hlthunk_get_device_name_from_fd(fd);
    return ((HLTHUNK_DEVICE_GAUDI == device) || (HLTHUNK_DEVICE_GAUDI_HL2000M == device));
}

int hl_memory_init(struct memory_ctx *ctx) {
    struct hl_memory_ctx *const hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
    hl_ctx->device_fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, hl_ctx->device_bus_id);
    if (hl_ctx->device_fd < 0) {
        return FAILURE;
    }

    hl_ctx->mem_handle_table = kh_init(uint64_t);
    if (!hl_ctx->mem_handle_table) {
        (void) hlthunk_close(hl_ctx->device_fd);
        return FAILURE;
    }

    if (0 != pthread_mutex_init(&hl_ctx->mem_handle_table_lock, NULL)) {
        (void) hlthunk_close(hl_ctx->device_fd);
        kh_destroy(uint64_t, hl_ctx->mem_handle_table);
        return FAILURE;
    }

    return SUCCESS;
}

int hl_memory_destroy(struct memory_ctx *ctx) {
    struct hl_memory_ctx *const hl_ctx = container_of(ctx, struct hl_memory_ctx, base);

    (void) pthread_mutex_destroy(&hl_ctx->mem_handle_table_lock);
    kh_destroy(uint64_t, hl_ctx->mem_handle_table);
    (void) hlthunk_close(hl_ctx->device_fd);

    free(hl_ctx);
    return SUCCESS;
}

int hl_memory_allocate_buffer(struct memory_ctx *ctx, int alignment, uint64_t size, int *dmabuf_fd,
                              uint64_t *dmabuf_offset, void **addr, bool *can_init) {
    struct hl_memory_ctx *const hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
    const uint64_t page_size = 0;
    const uint64_t NO_OFFSET = 0;
    const bool NOT_SHARED = false;
    int fd = INVALID_FD;
    uint64_t buffer_addr = 0;
    const size_t buf_size = (size + ACCEL_PAGE_SIZE - 1) & ~(ACCEL_PAGE_SIZE - 1);

    int rc;
    khint_t k;
    const uint64_t memory_handle = hlthunk_device_memory_alloc(hl_ctx->device_fd, buf_size, page_size,
                                                               HL_MEM_CONTIGUOUS, NOT_SHARED);
    if (0 == memory_handle) {
        fprintf(stderr, "Failed to allocate %lu bytes of device memory\n", buf_size);
        return FAILURE;
    }
    buffer_addr = hlthunk_device_memory_map(hl_ctx->device_fd, memory_handle, 0);
    if (0 == buffer_addr) {
        fprintf(stderr, "Failed to map device memory allocation\n");
        return FAILURE;
    }
    if (0 != pthread_mutex_lock(&hl_ctx->mem_handle_table_lock)) {
        fprintf(stderr, "Failed to lock mutex while allocating memory\n");
        return FAILURE;
    }
    k = kh_put(uint64_t, hl_ctx->mem_handle_table, buffer_addr, &rc);
    kh_val(hl_ctx->mem_handle_table, k) = memory_handle;
    if (0 != pthread_mutex_unlock(&hl_ctx->mem_handle_table_lock)) {
        fprintf(stderr, "Failed to unlock mutex\n");
        return FAILURE;
    }
    if (hl_is_gaudi1(hl_ctx->device_fd)) {
        fd = hlthunk_device_memory_export_dmabuf_fd(hl_ctx->device_fd, buffer_addr, buf_size, NO_OFFSET);
    } else {
        fd = hlthunk_device_mapped_memory_export_dmabuf_fd(hl_ctx->device_fd, buffer_addr, buf_size, NO_OFFSET,
                                                           O_RDWR | O_CLOEXEC);
    }

    if (fd < 0) {
        fprintf(stderr, "Failed to export dmabuf. sz[%lu] ptr[%p] err[%d]\n",
                (unsigned long) buf_size, (void *) buffer_addr, fd);
        return FAILURE;
    }

    fprintf(stderr, "Allocated %lu bytes of accelerator buffer at %p on fd %d\n",
            (unsigned long) buf_size, (void *) buffer_addr, fd);
    *dmabuf_fd = fd;
    *dmabuf_offset = 0;
    *addr = (void *) buffer_addr;
    *can_init = false;
    return SUCCESS;
}

int hl_memory_free_buffer(struct memory_ctx *ctx, int dmabuf_fd, void *addr, uint64_t size) {
    struct hl_memory_ctx *hl_ctx = container_of(ctx, struct hl_memory_ctx, base);
    uint64_t memory_handle = INVALID_FD;
    khint_t k;
    int rc = hlthunk_memory_unmap(hl_ctx->device_fd, (uint64_t) addr);

    if (rc) {
        fprintf(stderr, "Failed to unmap host memory\n");
        return rc;
    }
    if (0 != pthread_mutex_lock(&hl_ctx->mem_handle_table_lock)) {
        fprintf(stderr, "Failed to lock mutex while deallocating memory\n");
        return FAILURE;
    }
    k = kh_get(uint64_t, hl_ctx->mem_handle_table, (uintptr_t) addr);
    if (k == kh_end(hl_ctx->mem_handle_table)) {
        fprintf(stderr, "Failed to find memory handle handle\n");
        (void) pthread_mutex_unlock(&hl_ctx->mem_handle_table_lock);
        return FAILURE;
    }

    memory_handle = kh_val(hl_ctx->mem_handle_table, k);
    rc = hlthunk_device_memory_free(hl_ctx->device_fd, memory_handle);
    kh_del(uint64_t, hl_ctx->mem_handle_table, k);
    pthread_mutex_unlock(&hl_ctx->mem_handle_table_lock);
    return (0 == rc) ? SUCCESS : FAILURE;
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
