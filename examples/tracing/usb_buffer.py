#!/usr/bin/python3
#
# usb_buffer     Monitor usb buffer
# This is an example to display a buffer of USB inputs and outputs.
# It allows you to monitor the traffic that USB does, just like USBPcap.
#
# Copyright (c) 2020 gpioblink

from bcc import BPF
from hexdump import hexdump

code = """
#include <linux/usb.h>

struct data_t {
  u64 alen;
  u64 buflen;
  u16 vendor;
  u16 product;
  unsigned int transfer_flags;
  unsigned char buf[256];
};

BPF_PERF_OUTPUT(events);

// Instrument usb_hcd_giveback_urb() because the entity of
// the USB block containing the buffer passed by the USB driver is returned
int kprobe____usb_hcd_giveback_urb(struct pt_regs *ctx, struct urb *urb) {
  struct data_t data = {};
  
  // Get information on the USB device in order to identify the request
  struct usb_device *dev = urb->dev;
  data.vendor = dev->descriptor.idVendor;
  data.product = dev->descriptor.idProduct;
  data.transfer_flags = urb->transfer_flags; // whether to send or receive.
  data.alen = urb->actual_length;
  data.buflen = urb->transfer_buffer_length;
  
  // Retrieve data sent or received from the USB buffer
  bpf_probe_read_kernel(data.buf, sizeof(data.buf), urb->transfer_buffer);
  
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""

b = BPF(text=code)

def print_event(cpu, data, size):
  event = b["events"].event(data)
  print("[vendor = 0x%x, product = 0x%x] transfer_flags = %s, actual_length = %d, transfer_buffer_length = %d" % (event.vendor, event.product, judge_in_out(event.transfer_flags), event.alen, event.buflen))
  hexdump(bytes(event.buf[0:event.buflen]))
  print("")

def judge_in_out(transfer_flags):
  if transfer_flags & 0x0200 != 0:
    return "IN"
  return "OUT"

b["events"].open_perf_buffer(print_event)

while 1:
  b.perf_buffer_poll()
