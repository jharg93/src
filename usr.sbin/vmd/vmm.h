/*
 * Copyright (c) 2016 Mike Larkin <mlarkin@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define MAX_PORTS 65536

typedef uint8_t (*io_fn_t)(struct vm_run_params *);

void vcpu_assert_pic_irq(uint32_t, uint32_t, int);
void vcpu_deassert_pic_irq(uint32_t, uint32_t, int);
void set_return_data(struct vm_exit *, uint32_t);
void get_input_data(struct vm_exit *, uint32_t *);

typedef int (*iocb_t)(int, uint64_t, uint32_t, void *, void *);

struct iohandler {
	uint64_t start;
	uint64_t end;
	iocb_t handler;
	void *cookie;
	TAILQ_ENTRY(iohandler) next;
};

void register_mem(uint64_t base, uint32_t len, iocb_t handler, void *cookie);
void unregister_mem(uint64_t base);
int mem_handler(int dir, uint64_t addr, uint32_t size, void *data);
