/*
 * Standalone hardware test harness for the goodix533c driver.
 *
 * Not part of libfprint's public API or installed targets -- it reaches
 * straight into the driver's test-only entry point
 * (fpi_device_goodix533c_capture_test) because there is no enroll/verify
 * vfunc wired up yet (out of scope for this task). Builds only when
 * 'goodix533c' is in the enabled driver list (see libfprint/meson.build).
 *
 * Usage: goodix533c-capture-test [output.pgm]
 */

#include <errno.h>
#include <stdio.h>

#include <glib.h>

#include "fp-context.h"
#include "fp-device.h"

#include "drivers/goodix533c/goodix533c.h"

typedef struct
{
  GMainLoop *loop;
  const char *output_path;
  int         exit_code;
} TestState;

static gboolean
write_pgm (const char *path, const guint8 *pixels, int width, int height)
{
  FILE *f = fopen (path, "wb");
  size_t n;

  if (!f)
    {
      g_print ("Failed to open %s for writing: %s\n", path, g_strerror (errno));
      return FALSE;
    }

  fprintf (f, "P5\n%d %d\n255\n", width, height);
  n = fwrite (pixels, 1, (size_t) (width * height), f);
  fclose (f);

  return n == (size_t) (width * height);
}

static void
on_closed (FpDevice *dev, GAsyncResult *res, TestState *ts)
{
  g_autoptr(GError) error = NULL;

  fp_device_close_finish (dev, res, &error);
  if (error)
    g_print ("close() error: %s\n", error->message);
  else
    g_print ("close() OK\n");

  g_main_loop_quit (ts->loop);
}

static void
on_capture_done (FpDevice *dev, const guint16 *raw_pixels,
                 const guint8 *squashed, gpointer user_data, GError *error)
{
  TestState *ts = user_data;
  int count = GOODIX533C_SENSOR_WIDTH * GOODIX533C_SENSOR_HEIGHT;
  int i;
  guint16 raw_min = 0xffff;
  guint16 raw_max = 0;

  if (error)
    {
      g_print ("Capture FAILED: %s\n", error->message);
      ts->exit_code = 1;
      fp_device_close (dev, NULL, (GAsyncReadyCallback) on_closed, ts);
      return;
    }

  for (i = 0; i < count; i++)
    {
      if (raw_pixels[i] < raw_min)
        raw_min = raw_pixels[i];
      if (raw_pixels[i] > raw_max)
        raw_max = raw_pixels[i];
    }

  g_print ("Captured frame: %dx%d, raw pixel range [%u, %u]\n",
           GOODIX533C_SENSOR_WIDTH, GOODIX533C_SENSOR_HEIGHT, raw_min,
           raw_max);

  if (write_pgm (ts->output_path, squashed, GOODIX533C_SENSOR_WIDTH,
                 GOODIX533C_SENSOR_HEIGHT))
    g_print ("Wrote %s\n", ts->output_path);
  else
    {
      g_print ("Failed to write %s\n", ts->output_path);
      ts->exit_code = 1;
    }

  fp_device_close (dev, NULL, (GAsyncReadyCallback) on_closed, ts);
}

static void
on_opened (FpDevice *dev, GAsyncResult *res, TestState *ts)
{
  g_autoptr(GError) error = NULL;

  if (!fp_device_open_finish (dev, res, &error))
    {
      g_print ("open() FAILED: %s\n", error ? error->message : "(no error set)");
      ts->exit_code = 1;
      g_main_loop_quit (ts->loop);
      return;
    }

  g_print ("open() SUCCEEDED\n");
  fpi_device_goodix533c_capture_test (dev, on_capture_done, ts);
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) ctx = NULL;
  GPtrArray *devices;
  FpDevice *dev = NULL;
  TestState ts = { 0 };
  guint i;

  ts.output_path = argc > 1 ? argv[1] : "goodix533c-capture.pgm";

  ctx = fp_context_new ();
  devices = fp_context_get_devices (ctx);

  if (!devices || devices->len == 0)
    {
      g_print ("No fingerprint devices found at all.\n");
      return 1;
    }

  for (i = 0; i < devices->len; ++i)
    {
      FpDevice *d = g_ptr_array_index (devices, i);

      g_print ("Found: %s (%s) - driver %s\n",
               fp_device_get_device_id (d), fp_device_get_name (d),
               fp_device_get_driver (d));
      if (g_strcmp0 (fp_device_get_driver (d), "goodix533c") == 0)
        dev = d;
    }

  if (!dev)
    {
      g_print ("No goodix533c device found among the above.\n");
      return 1;
    }

  ts.loop = g_main_loop_new (NULL, FALSE);
  g_print ("Opening %s ...\n", fp_device_get_device_id (dev));
  fp_device_open (dev, NULL, (GAsyncReadyCallback) on_opened, &ts);
  g_main_loop_run (ts.loop);
  g_main_loop_unref (ts.loop);

  return ts.exit_code;
}
