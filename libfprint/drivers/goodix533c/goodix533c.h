/*
 * Goodix 27c6:533c native driver for libfprint
 *
 * Copyright (C) 2026 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This driver targets a single goal: FpDevice open() succeeding against
 * real 27c6:533c hardware, followed by capture of one raw frame.  It is
 * rooted directly at FP_TYPE_DEVICE (not FpImageDevice, not
 * FpiDeviceGoodixTls) because 533c's finger-detect/calibration sequence is
 * fundamentally session-dynamic (see measure_baseline() in
 * driver_53xc.py / findings/native-driver-architecture.md) and does not
 * fit goodix5xx.c's shared FDT state machine, which assumes a static
 * config blob sourced from a no-argument class vfunc.
 *
 * The wire-level checksum/framing codec (goodix_proto.c/.h) and the
 * embedded TLS-PSK server (goodixtls.c/.h) are reused unmodified from the
 * sibling goodixtls/ driver directory -- both are already device-agnostic.
 * Everything else here is new, ported from the *logic* (not the compiled
 * functions -- those are hard-tied to FpiDeviceGoodixTls) of goodix.c,
 * cross-checked stage for stage against vendor/goodix-fp-dump-nikicat's
 * driver_53xc.py, which is authoritative for this exact silicon.
 */

#pragma once

#include "fpi-device.h"

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix533c, fpi_device_goodix533c, FPI,
                      DEVICE_GOODIX533C, FpDevice)

#define FPI_TYPE_DEVICE_GOODIX533C (fpi_device_goodix533c_get_type ())

#define GOODIX533C_SENSOR_WIDTH  (108)
#define GOODIX533C_SENSOR_HEIGHT (88)

/**
 * Goodix533cCaptureDoneFunc: callback for the test-only capture entry
 * point below.
 *
 * @raw_pixels: (nullable): GOODIX533C_SENSOR_WIDTH * GOODIX533C_SENSOR_HEIGHT
 *   12-bit-ish samples (one guint16 per pixel, unpacked straight off the
 *   wire -- not squashed), owned by the callee, valid only for the
 *   duration of the callback. NULL on error.
 * @squashed: (nullable): the same frame min-max stretched to 8 bits per
 *   pixel, row-major, GOODIX533C_SENSOR_WIDTH * GOODIX533C_SENSOR_HEIGHT
 *   bytes. NULL on error.
 */
typedef void (*Goodix533cCaptureDoneFunc)(FpDevice *dev,
                                          const guint16 *raw_pixels,
                                          const guint8  *squashed,
                                          gpointer       user_data,
                                          GError        *error);

/**
 * fpi_device_goodix533c_capture_test:
 *
 * Not public libfprint API -- a test-only entry point for driving the
 * reset -> PSK/firmware check (already done by open()) -> TLS handshake ->
 * config upload -> FDT baseline -> one-frame capture sequence, for use by
 * a standalone test harness after fp_device_open() has completed. Must
 * only be called once per open() session.
 */
void fpi_device_goodix533c_capture_test (FpDevice                  *dev,
                                         Goodix533cCaptureDoneFunc  callback,
                                         gpointer                   user_data);
