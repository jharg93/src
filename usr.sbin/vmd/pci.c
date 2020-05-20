/*	$OpenBSD: pci.c,v 1.28 2019/10/16 02:47:34 mlarkin Exp $	*/

/*
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
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

#include <sys/types.h>

#include <sys/ioctl.h>
#include <sys/pciio.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcidevs.h>
#include <dev/pv/virtioreg.h>
#include <machine/vmmvar.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vmd.h"
#include "pci.h"
#include "vmm.h"
#include "i8259.h"
#include "atomicio.h"
#include <sys/pciio.h>
#include <sys/mman.h>

struct pci pci;

extern struct vmd *env;

extern char *__progname;

/* PIC IRQs, assigned to devices in order */
const uint8_t pci_pic_irqs[PCI_MAX_PIC_IRQS] = {3, 5, 6, 7, 9, 10, 11, 12,
    14, 15};

void _pcicfgwr32(int id, int reg, uint32_t data);
void _pcicfgwr32(int id, int reg, uint32_t data) {
  pci.pci_devices[id].pd_cfg_space[reg/4] = data;
}

int pci_memh2(int, uint64_t, uint32_t, void *, void *);
uint64_t mbar(int, uint64_t *base, uint32_t size, uint32_t align);

#define PAGE_MASK 0xFFF

void dump(void *ptr, int len);

struct vm_barinfo bi;
void *barva[MAXBAR];

/* Map a MMIO Bar address */
void *mapbar(uint64_t base, uint64_t size);
void unmapbar(void *va, uint64_t size);
void unmapbar(void *va, uint64_t size) {
	if (va == NULL)
		return;
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	munmap(va, size);
	fprintf(stderr, "unmapping bar: %p/%.8llx\n", va, size);
}
void *mapbar(uint64_t base, uint64_t size) {
	void *va;

	size = (size + PAGE_MASK) & ~PAGE_MASK;
	va = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, env->vmd_fd, base);
	if (va == (void *)-1ULL) {
		fprintf(stderr, "Unable to mmap bar: %.16llx/%.8llx\n",
			base, size);
		return NULL;
	}
	fprintf(stderr, "Mapped bar: %.16llx/%.8llx to %p\n",
		base, size, va);
	dump(va, size);
	return va;
}

int pci_memh2(int dir, uint64_t base, uint32_t size, void *data, void *cookie)
{
	int dev = (uintptr_t)cookie;
	uint64_t hpa, off, mask;
	uint8_t barid = (uint8_t)(uintptr_t)cookie;
	uint8_t *va;

	off = (base & PAGE_MASK);
	hpa = bi.bars[barid].addr;

	if (size == 1)
		mask = 0xff;
	else if (size == 2)
		mask = 0xffff;
	else if (size == 4)
		mask = 0xffffffff;
#if 0
	fprintf(stderr, "entry memh2 %c%d: %.16llx %.16llx %.4x\n", dir == VEI_DIR_IN ? 'r' : 'w', size,
		base, hpa, dev);
#endif
	va = barva[barid];
	if (va == NULL) {
		return -1;
	}
	if (dir == VEI_DIR_IN) {
		memcpy(data, va + off, size);
		fprintf(stderr, "  memh_rd%d: %.16llx %.16llx %p\n", 
			size, base, *(uint64_t *)data & mask, cookie);
	}
	else if (1) {
		fprintf(stderr, "  memh_wr%d: %.16llx %.16llx %p\n", 
			size, base, *(uint64_t *)data & mask, cookie);
		fflush(stdout);
		memcpy(va + off, data, size);
	}
	return 0;
}

/*
 * pci_add_bar
 *
 * Adds a BAR for the PCI device 'id'. On access, 'barfn' will be
 * called, and passed 'cookie' as an identifier.
 *
 * BARs are fixed size, meaning all I/O BARs requested have the
 * same size and all MMIO BARs have the same size.
 *
 * Parameters:
 *  id: PCI device to add the BAR to (local count, eg if id == 4,
 *      this BAR is to be added to the VM's 5th PCI device)
 *  type: type of the BAR to add (PCI_MAPREG_TYPE_xxx)
 *  barfn: callback function invoked on BAR access
 *  cookie: cookie passed to barfn on access
 *
 * Returns 0 if the BAR was added successfully, 1 otherwise.
 */
int
pci_add_bar(uint8_t id, uint32_t type, uint32_t sz, uint32_t flag, void *barfn, void *cookie)
{
	uint8_t bar_reg_idx, bar_ct;
	uint64_t base = 0;

	/* Check id */
	if (id >= pci.pci_dev_ct)
		return (1);

	/* Can only add PCI_MAX_BARS BARs to any device */
	bar_ct = pci.pci_devices[id].pd_bar_ct;
	if (bar_ct >= PCI_MAX_BARS)
		return (1);

	/* Compute BAR address and add */
	bar_reg_idx = (PCI_MAPREG_START + (bar_ct * 4)) / 4;
	if (type == PCI_MAPREG_TYPE_MEM) {
		if (pci.pci_next_mmio_bar + sz >= VMM_PCI_MMIO_BAR_END)
			return (1);

		// Page align makes easier mapping
		base = mbar(bar_reg_idx, &pci.pci_next_mmio_bar, sz, 4096);
		pci.pci_devices[id].pd_cfg_space[bar_reg_idx] = 
		    PCI_MAPREG_MEM_ADDR(base);
		pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
		pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;
		pci.pci_devices[id].pd_bartype[bar_ct] = PCI_BAR_TYPE_MMIO;
		pci.pci_devices[id].pd_barsize[bar_ct] = sz;
		pci.pci_devices[id].pd_bar_ct++;
	} else if (type == PCI_MAPREG_TYPE_IO) {
		if (pci.pci_next_io_bar + sz >= VMM_PCI_IO_BAR_END)
			return (1);

		base = mbar(bar_reg_idx, &pci.pci_next_io_bar, sz, 4);
		pci.pci_devices[id].pd_cfg_space[bar_reg_idx] = 
		    PCI_MAPREG_IO_ADDR(base) |
		    PCI_MAPREG_TYPE_IO;
		pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
		pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;
		DPRINTF("%s: adding pci bar cookie for dev %d bar %d = %p",
		    __progname, id, bar_ct, cookie);
		pci.pci_devices[id].pd_bartype[bar_ct] = PCI_BAR_TYPE_IO;
		pci.pci_devices[id].pd_barsize[bar_ct] = sz;
		pci.pci_devices[id].pd_bar_ct++;
	}

	return (0);
}

int
pci_set_bar_fn(uint8_t id, uint8_t bar_ct, void *barfn, void *cookie)
{
	/* Check id */
	if (id >= pci.pci_dev_ct)
		return (1);

	if (bar_ct >= PCI_MAX_BARS)
		return (1);

	pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
	pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;

	return (0);
}

/*
 * pci_get_dev_irq
 *
 * Returns the IRQ for the specified PCI device
 *
 * Parameters:
 *  id: PCI device id to return IRQ for
 *
 * Return values:
 *  The IRQ for the device, or 0xff if no device IRQ assigned
 */
uint8_t
pci_get_dev_irq(uint8_t id)
{
	if (pci.pci_devices[id].pd_int)
		return pci.pci_devices[id].pd_irq;
	else
		return 0xFF;
}

/*
 * pci_add_device
 *
 * Adds a PCI device to the guest VM defined by the supplied parameters.
 *
 * Parameters:
 *  id: the new PCI device ID (0 .. PCI_CONFIG_MAX_DEV)
 *  vid: PCI VID of the new device
 *  pid: PCI PID of the new device
 *  class: PCI 'class' of the new device
 *  subclass: PCI 'subclass' of the new device
 *  subsys_vid: subsystem VID of the new device
 *  subsys_id: subsystem ID of the new device
 *  irq_needed: 1 if an IRQ should be assigned to this PCI device, 0 otherwise
 *  csfunc: PCI config space callback function when the guest VM accesses
 *      CS of this PCI device
 *
 * Return values:
 *  0: the PCI device was added successfully. The PCI device ID is in 'id'.
 *  1: the PCI device addition failed.
 */
int
pci_add_device(uint8_t *id, uint16_t vid, uint16_t pid, uint8_t class,
    uint8_t subclass, uint16_t subsys_vid, uint16_t subsys_id,
    uint8_t irq_needed, pci_cs_fn_t csfunc, void *cookie)
{
	log_warnx("%s: add_pci: %x.%x.%x\n", __progname, vid, pid, class);

	/* Exceeded max devices? */
	if (pci.pci_dev_ct >= PCI_CONFIG_MAX_DEV)
		return (1);

	/* Exceeded max IRQs? */
	/* XXX we could share IRQs ... */
	if (pci.pci_next_pic_irq >= PCI_MAX_PIC_IRQS && irq_needed)
		return (1);

	*id = pci.pci_dev_ct;

	pci.pci_devices[*id].pd_vid = vid;
	pci.pci_devices[*id].pd_did = pid;
	pci.pci_devices[*id].pd_class = class;
	pci.pci_devices[*id].pd_subclass = subclass;
	pci.pci_devices[*id].pd_subsys_vid = subsys_vid;
	pci.pci_devices[*id].pd_subsys_id = subsys_id;

	pci.pci_devices[*id].pd_csfunc = csfunc;
	pci.pci_devices[*id].pd_cookie = cookie;

	if (irq_needed) {
		pci.pci_devices[*id].pd_irq =
		    pci_pic_irqs[pci.pci_next_pic_irq];
		pci.pci_devices[*id].pd_int = 1;
		pci.pci_next_pic_irq++;
		DPRINTF("assigned irq %d to pci dev %d",
		    pci.pci_devices[*id].pd_irq, *id);
		pic_set_elcr(pci.pci_devices[*id].pd_irq, 1);
	}

	pci.pci_dev_ct ++;

	return (0);
}

/* Allocate an aligned BAR address */
uint64_t mbar(int idx, uint64_t *base, uint32_t size, uint32_t align)
{
	uint64_t mask = align-1;
	uint64_t cbase;

	cbase = (*base + mask) & ~mask;
	*base = (*base + size + mask) & ~mask;
	fprintf(stderr,"make mbar%d: %llx/%x\n", idx, cbase, size);
	return cbase;
}

void pci_add_pthru(struct vmd_vm *vm, int bus, int dev, int fun);

#define PCIOCUNBIND	_IOWR('p', 9, struct pcisel)

int ppt_csfn(int dir, uint8_t reg, uint8_t sz, uint32_t *data, void *cookie);
int ppt_iobar(int dir, uint16_t reg, uint32_t *data, uint8_t *intr, void *cookie, uint8_t size);
int ppt_mmiobar(int dir, uint32_t ofs, uint32_t *data);

int ppt_csfn(int dir, uint8_t reg, uint8_t sz, uint32_t *data, void *cookie)
{
	return 0;
}

/* Callback for I/O ports. Map to new I/O port and do it */
int ppt_iobar(int dir, uint16_t reg, uint32_t *data, uint8_t *intr, void *cookie, uint8_t size)
{
	uint8_t barid = (uintptr_t)cookie;
	struct vm_pio pio;
	uint64_t mask;

	if (size == 1)
		mask = 0xff;
	else if (size == 2)
		mask = 0xffff;
	else if (size == 4)
		mask = 0xffffffff;

	/* Remap to phys bar address */	
	pio.dir = dir;
	pio.size = size;
	pio.port = bi.bars[barid].addr + reg;
	if (dir == VEI_DIR_OUT) {
		fprintf(stderr,"iobar: %s%d(%.4llx,%llx)\n",
			dir == VEI_DIR_OUT ? "out" : "in", size, 
			bi.bars[barid].addr+reg, *data & mask);
		pio.data = *data & mask;
		ioctl(env->vmd_fd, VMM_IOC_PIO, &pio);
	}
	else  {
		ioctl(env->vmd_fd, VMM_IOC_PIO, &pio);
		*data = (*data & ~mask) | (pio.data & mask);
		fprintf(stderr,"iobar: %s%d(%.4llx,%llx)\n",
			dir == VEI_DIR_OUT ? "out" : "in", size, 
			bi.bars[barid].addr+reg, *data & mask);
	}
	return 0;
}

int ppt_mmiobar(int dir, uint32_t ofs, uint32_t *data)
{
	fprintf(stderr,"mmiobar: %d.%x\n", dir, ofs);
	return 0;
}

void dump(void *ptr, int len)
{
  int i, j, c;
  unsigned char *b = ptr;

  for (i = 0; i < len; i+=16) {
    fprintf(stderr,"%.4x ", i);
    for (j = 0; j < 16; j++) {
      fprintf(stderr,"%.2x ", b[i+j]);
    }
    fprintf(stderr,"  ");
    for (j = 0; j < 16; j++) {
      c = b[i+j];
      if (c < ' ' || c > 'z') c = '.';
      fprintf(stderr,"%c", c);
    }
    fprintf(stderr,"\n");
  }
}

void pci_add_pthru(struct vmd_vm *vm, int bus, int dev, int fun)
{
	static uint8_t id;
	static struct pcisel ptd;
	uintptr_t devid;
	int i;

	for (i = 0; i < MAXBAR; i++) {
		if (barva[i]) {
			unmapbar(barva[i], bi.bars[i].size);
		}
	}
	ptd.pc_bus = bus;
	ptd.pc_dev = dev;
	ptd.pc_func = fun;
	if (bus == 17) {
		pci_add_device(&id, 0x1217, 0x8520, 8, 5, 0x1028, 0x5cc, 1, NULL, &ptd);
	}
	else if (dev == 25) {
		pci_add_device(&id, 0x8086, 0x153a, 0x02, 0, 0x1028, 0x5cc, 1, NULL, &ptd);
	}
	else  {
		pci_add_device(&id, 0x8086, 0x8c22, 0xc, 5, 0x1028, 0x5cc, 1, NULL, &ptd);
		_pcicfgwr32(id, 0x40, 0x11);
	}

	/* Get BARs of native device */
	bi.seg = 0;
	bi.bus = bus;
	bi.dev = dev;
	bi.func = fun;
	ioctl(env->vmd_fd, VMM_IOC_BARINFO,  &bi);
	for (i = 0; i < MAXBAR; i++) {
		devid = (id << 8) | i;
		fprintf(stderr,"Bar%d: type:%x base:%llx size:%x\n",
			i, bi.bars[i].type, bi.bars[i].addr, bi.bars[i].size);
		bi.bars[i].type &= 0x1;
		if (bi.bars[i].type == PCI_MAPREG_TYPE_MEM && bi.bars[i].size) {
			pci_add_bar(id, PCI_MAPREG_TYPE_MEM, bi.bars[i].size, 1, ppt_mmiobar, (void *)devid);
			barva[i] = mapbar(bi.bars[i].addr, bi.bars[i].size);
		}
		else if (bi.bars[i].type == PCI_MAPREG_TYPE_IO) {
			/* This will get callback via pci_handle_io */
			pci_add_bar(id, PCI_MAPREG_TYPE_IO,  bi.bars[i].size, 1, ppt_iobar, (void *)devid);
		}
		else {
			/* Kick bar index */
			pci.pci_devices[id].pd_bar_ct++;
		}
	}
}

/*
 * pci_init
 *
 * Initializes the PCI subsystem for the VM by adding a PCI host bridge
 * as the first PCI device.
 */
void
pci_init(void)
{
	uint8_t id;

	memset(&pci, 0, sizeof(pci));
	pci.pci_next_mmio_bar = VMM_PCI_MMIO_BAR_BASE;
	pci.pci_next_io_bar = VMM_PCI_IO_BAR_BASE;

	if (pci_add_device(&id, PCI_VENDOR_OPENBSD, PCI_PRODUCT_OPENBSD_PCHB,
	    PCI_CLASS_BRIDGE, PCI_SUBCLASS_BRIDGE_HOST,
	    PCI_VENDOR_OPENBSD, 0, 0, NULL, NULL)) {
		log_warnx("%s: can't add PCI host bridge", __progname);
		return;
	}
}

void
pci_handle_address_reg(struct vm_run_params *vrp)
{
	struct vm_exit *vei = vrp->vrp_exit;

	/*
	 * vei_dir == VEI_DIR_OUT : out instruction
	 *
	 * The guest wrote to the address register.
	 */
	if (vei->vei.vei_dir == VEI_DIR_OUT) {
		get_input_data(vei, &pci.pci_addr_reg);
	} else {
		/*
		 * vei_dir == VEI_DIR_IN : in instruction
		 *
		 * The guest read the address register
		 */
		set_return_data(vei, pci.pci_addr_reg);
	}
}

uint8_t
pci_handle_io(struct vm_run_params *vrp)
{
	int i, j, k, l;
	uint16_t reg, b_hi, b_lo;
	pci_iobar_fn_t fn;
	struct vm_exit *vei = vrp->vrp_exit;
	uint8_t intr, dir;

	k = -1;
	l = -1;
	reg = vei->vei.vei_port;
	dir = vei->vei.vei_dir;
	intr = 0xFF;

	for (i = 0 ; i < pci.pci_dev_ct ; i++) {
		for (j = 0 ; j < pci.pci_devices[i].pd_bar_ct; j++) {
			b_lo = PCI_MAPREG_IO_ADDR(pci.pci_devices[i].pd_bar[j]);
			b_hi = b_lo + VMM_PCI_IO_BAR_SIZE;
			if (reg >= b_lo && reg < b_hi) {
				if (pci.pci_devices[i].pd_barfunc[j]) {
					k = j;
					l = i;
				}
			}
		}
	}

	if (k >= 0 && l >= 0) {
		fn = (pci_iobar_fn_t)pci.pci_devices[l].pd_barfunc[k];
		if (fn(vei->vei.vei_dir, reg -
		    PCI_MAPREG_IO_ADDR(pci.pci_devices[l].pd_bar[k]),
		    &vei->vei.vei_data, &intr,
		    pci.pci_devices[l].pd_bar_cookie[k],
		    vei->vei.vei_size)) {
			log_warnx("%s: pci i/o access function failed",
			    __progname);
		}
	} else {
		fprintf(stderr,"%s: no pci i/o function for reg 0x%llx (dir=%d "
		    "guest %%rip=0x%llx", __progname, (uint64_t)reg, dir,
		    vei->vrs.vrs_gprs[VCPU_REGS_RIP]);
		/* Reads from undefined ports return 0xFF */
		if (dir == VEI_DIR_IN)
			set_return_data(vei, 0xFFFFFFFF);
	}

	if (intr != 0xFF) {
		intr = pci.pci_devices[l].pd_irq;
	}

	return (intr);
}

void
pci_handle_data_reg(struct vm_run_params *vrp)
{
	struct vm_exit *vei = vrp->vrp_exit;
	uint8_t b, d, f, o, baridx, ofs, sz;
	uint32_t data;
	uint64_t wrdata;
	int ret, flag = 0;
	pci_cs_fn_t csfunc;

	/* abort if the address register is wack */
	if (!(pci.pci_addr_reg & PCI_MODE1_ENABLE)) {
		/* if read, return FFs */
		if (vei->vei.vei_dir == VEI_DIR_IN)
			set_return_data(vei, 0xFFFFFFFF);
		log_warnx("invalid address register during pci read: "
		    "0x%llx", (uint64_t)pci.pci_addr_reg);
		return;
	}

	/* I/Os to 0xCFC..0xCFF are permitted */
	ofs = vei->vei.vei_port - 0xCFC;
	sz = vei->vei.vei_size;

	b = (pci.pci_addr_reg >> 16) & 0xff;
	d = (pci.pci_addr_reg >> 11) & 0x1f;
	f = (pci.pci_addr_reg >> 8) & 0x7;
	o = (pci.pci_addr_reg & 0xfc);

	wrdata = vei->vei.vei_data;
	data = 0;
	if (d < pci.pci_dev_ct && !b && !f) {
		data = pci.pci_devices[d].pd_cfg_space[o/4];
	}
	
	csfunc = pci.pci_devices[d].pd_csfunc;
	if (csfunc != NULL) {
		ret = csfunc(vei->vei.vei_dir, o, sz, &vei->vei.vei_data,
			     pci.pci_devices[d].pd_cookie);
		if (ret)
			log_warnx("cfg space access function failed for "
			    "pci device %d", d);
		return;
	}

	/* No config space function, fallback to default simple r/w impl. */

	o += ofs;
	
	/*
	 * vei_dir == VEI_DIR_OUT : out instruction
	 *
	 * The guest wrote to the config space location denoted by the current
	 * value in the address register.
	 */
	if (d == 110) {
		fprintf(stderr, "@@ pci_conf_%s(%.2x,cur:%llx,new:%llx)\n",
			vei->vei.vei_dir == VEI_DIR_OUT ? "wr" : "rd",
			o, pci.pci_devices[d].pd_cfg_space[o/4],
			vei->vei.vei_data);
	}
	if (o >= 0x10 && o <= 0x24 && 0)  {
		fprintf(stderr,"accbar: %c %x.%x.%x %x [%x %x]\n", 
			vei->vei.vei_dir == VEI_DIR_OUT  ? 'w' : 'r', b,d,f,o,
			pci.pci_devices[d].pd_cfg_space[o/4],
			vei->vei.vei_data);
	}
	if (vei->vei.vei_dir == VEI_DIR_OUT) {
		if ((o >= 0x10 && o <= 0x24) &&
		    vei->vei.vei_data == 0xffffffff) {
			/*
			 * Compute BAR index:
			 * o = 0x10 -> baridx = 0
			 * o = 0x14 -> baridx = 1
			 * o = 0x18 -> baridx = 2
			 * o = 0x1c -> baridx = 3
			 * o = 0x20 -> baridx = 4
			 * o = 0x24 -> baridx = 5
			 */
			baridx = (o / 4) - 4;
			if (baridx < pci.pci_devices[d].pd_bar_ct) {
				vei->vei.vei_data = ~(pci.pci_devices[d].pd_barsize[baridx] - 1);
			}
			else
				vei->vei.vei_data = 0;
		}

		/* IOBAR registers must have bit 0 set */
		if (o >= 0x10 && o <= 0x24) {
			baridx = (o / 4) - 4;
			if (baridx < pci.pci_devices[d].pd_bar_ct &&
			    pci.pci_devices[d].pd_bartype[baridx] ==
			    PCI_BAR_TYPE_IO)
				vei->vei.vei_data |= 1;
			if (baridx < pci.pci_devices[d].pd_bar_ct &&
			    pci.pci_devices[d].pd_bartype[baridx] ==
			    PCI_BAR_TYPE_MMIO && wrdata != 0xffffffff) {
				fprintf(stderr, "%.2x old/new: %.8x %.8llx/%.8x ip:%.16llx\n", o,
					pci.pci_devices[d].pd_cfg_space[o / 4],
					wrdata, 
					pci.pci_devices[d].pd_barsize[(o - 0x10)/4],
					vei->vrs.vrs_gprs[VCPU_REGS_RIP]);
				unregister_mem(pci.pci_devices[d].pd_cfg_space[o/4]);
				register_mem(wrdata, pci.pci_devices[d].pd_barsize[(o - 0x10)/4],
					pci_memh2,
					(void *)(uintptr_t)(d << 8) + ((o - 0x10) / 4));
			}
		}

		/*
		 * Discard writes to "option rom base address" as none of our
		 * emulated devices have PCI option roms. Accept any other
		 * writes and copy data to config space registers.
		 */
		if (o != PCI_EXROMADDR_0)
			get_input_data(vei,
			    &pci.pci_devices[d].pd_cfg_space[o / 4]);
	} else {
		/*
		 * vei_dir == VEI_DIR_IN : in instruction
		 *
		 * The guest read from the config space location determined by
		 * the current value in the address register.
		 */
		if (d > pci.pci_dev_ct || b > 0 || f > 0)
			set_return_data(vei, 0xFFFFFFFF);
		else {
			switch (sz) {
			case 4:
				set_return_data(vei, data);
				break;
			case 2:
				if (ofs == 0)
					set_return_data(vei, data);
				else
					set_return_data(vei, data >> 16);
				break;
			case 1:
				set_return_data(vei, data >> (ofs * 8));
				break;
			}
		}
	}
}

int
pci_dump(int fd)
{
	log_debug("%s: sending pci", __func__);
	if (atomicio(vwrite, fd, &pci, sizeof(pci)) != sizeof(pci)) {
		log_warnx("%s: error writing pci to fd", __func__);
		return (-1);
	}
	return (0);
}

int
pci_restore(int fd)
{
	log_debug("%s: receiving pci", __func__);
	if (atomicio(read, fd, &pci, sizeof(pci)) != sizeof(pci)) {
		log_warnx("%s: error reading pci from fd", __func__);
		return (-1);
	}
	return (0);
}
