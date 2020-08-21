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

#define PTD_DEVID(d,b)   (void *)(uintptr_t)(((d) << 8) | (b))
#define PTD_BAR(x)       ((uintptr_t)(x) & 0xFF)
#define PTD_DEV(x)       ((uintptr_t)(x) >> 8)

struct pci_ptd ptd;

uint32_t ptd_conf_read(int, int, int, uint32_t);
void ptd_conf_write(int, int, int, uint32_t reg, uint32_t val);
void io_copy(void *, const void *, int);
int mem_chkint(void);

/* Some helper functions */
void	 _pcicfgwr32(int, int, uint32_t);
uint32_t _pcicfgrd32(int, int);

void _pcicfgwr32(int id, int reg, uint32_t data) {
  pci.pci_devices[id].pd_cfg_space[reg/4] = data;
}
uint32_t _pcicfgrd32(int id, int reg) {
  return pci.pci_devices[id].pd_cfg_space[reg/4];
}

int pci_memh2(int, uint64_t, uint32_t, void *, void *);

#define PAGE_MASK 0xFFF

void dump(void *, int);

void *mapbar(int, uint64_t, uint64_t);
void unmapbar(void *, uint64_t);
void showremap(struct pci_ptd *);
void remap_io(int, int, int, int *, int *);
void do_pio(int, int, int, int, uint32_t *);

/* Map/Unmap a MMIO Bar address */
void *
mapbar(int bar, uint64_t base, uint64_t size) {
	uint8_t *va;

	if (!base || !size)
		return NULL;
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	va = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, env->vmd_fd, base & ~PAGE_MASK);
	if (va == (void *)-1ULL) {
		fprintf(stderr, "Unable to mmap bar: %.16llx/%.8llx\n",
			base, size);
		return NULL;
	}
	fprintf(stderr, "0x%.2x: Mapped bar: %.16llx/%.8llx to %p\n",
		(bar * 4) + 0x10, base, size, va);
	return va + (base & PAGE_MASK);
}

void
unmapbar(void *va, uint64_t size) {
	if (va == NULL)
		return;
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	munmap(va, size);
	fprintf(stderr, "unmapping bar: %p/%.8llx\n", va, size);
}

void
showremap(struct pci_ptd *pd)
{
	int i;

	fprintf(stderr,"================= device %d\n", pd->id);
	for (i = 0; i < MAXBAR; i++) {
		if (pd->barinfo[i].size) {
			fprintf(stderr,"  Bar%d: %.16x/%.8x -> %.16llx:%p\n",
				i, pci.pci_devices[pd->id].pd_cfg_space[i + 4],
				pd->barinfo[i].size,
				pd->barinfo[i].addr,
				pd->barinfo[i].va);
		}
	}
}

/* Get remapped addresses for host/guest */
void
remap_io(int dev, int bar, int reg, int *hport, int *gport)
{
	*hport = ptd.barinfo[bar].addr + reg;
	*gport = (_pcicfgrd32(dev, (bar * 4) + 0x10) & ~0x1) + reg;
}

void
do_pio(int type, int dir, int port, int size, uint32_t *data)
{
	struct vm_pio pio;
	uint64_t mask;

	if (size == 1)
		mask = 0xff;
	else if (size == 2)
		mask = 0xffff;
	else if (size == 4)
		mask = 0xffffffff;

	pio.dir = dir;
	pio.size = size;
	pio.base = port;
	if (dir == VEI_DIR_OUT) {
		pio.data = *data & mask;
		ioctl(env->vmd_fd, VMM_IOC_PIO, &pio);
	}
	else {
		ioctl(env->vmd_fd, VMM_IOC_PIO, &pio);
		*data = (*data & ~mask) | (pio.data & mask);
	}
	fprintf(stderr, "pio: %d/%.4x %.8x\n", dir, port, *data);
}

/* Passthrough PCI config read/write */
uint32_t
ptd_conf_read(int bus, int dev, int func, uint32_t reg)
{
	struct vm_pciio pio;

	memset(&pio, 0, sizeof(pio));
	pio.bus = bus;
	pio.dev = dev;
	pio.func = func;
	pio.dir = VEI_DIR_IN;
	pio.reg = reg & ~0x3;
	ioctl(env->vmd_fd, VMM_IOC_PCIIO, &pio);
	return pio.val;
}

void
ptd_conf_write(int bus, int dev, int func, uint32_t reg, uint32_t val)
{
	struct vm_pciio pio;

	memset(&pio, 0, sizeof(pio));
	pio.bus = bus;
	pio.dev = dev;
	pio.func = func;
	pio.dir = VEI_DIR_OUT;
	pio.reg = reg & ~0x3;
	pio.val = val;
	ioctl(env->vmd_fd, VMM_IOC_PCIIO, &pio);
}

int
mem_chkint(void)
{
	struct vm_getintr si;
	struct pci_ptd *pd;
	uint8_t intr = 0xff;
	int rc, i;

	for (i = 0; i < pci.pci_dev_ct; i++) {
		pd = &ptd;
		si.bus = pd->bus;
		si.dev = pd->dev;
		si.func = pd->fun;
		rc = ioctl(env->vmd_fd, VMM_IOC_GETINTR, &si);
		if (pd->pending != si.pending) {
			//fprintf(stderr, "pend:%d %d %d\n", pd->pending, si.pending, rc);
			intr = pci.pci_devices[pd->id].pd_irq;
			pd->pending = si.pending;
			return intr;
		}
	}
	return intr;
}

void
io_copy(void *dest, const void *src, int size) {
	memcpy(dest, src, size);
	return;
	if (size == 1)
		*(uint8_t *)dest = *(const uint8_t *)src;
	else if (size == 2)
		*(uint16_t *)dest = *(const uint16_t *)src;
	else if (size == 4)
		*(uint32_t *)dest = *(const uint32_t *)src;
	else if (size == 8)
		*(uint64_t *)dest = *(const uint64_t *)src;
}

/*
 * PCI Passthrough MMIO handler
 * USe memory mapped address of physical bar
 */
int
pci_memh2(int dir, uint64_t base, uint32_t size, void *data, void *cookie)
{
	uint64_t off;
	uint8_t barid = (uint8_t)(uintptr_t)cookie;
	struct pci_ptd *pd;
	uint8_t *va;

	pd = &ptd;
	off = base & (pd->barinfo[barid].size - 1);
	va = pd->barinfo[barid].va;
	if (va == NULL) {
		return -1;
	}
	if (dir == VEI_DIR_IN) {
		io_copy(data, va + off, size);
	}
	else {
		io_copy(va + off, data, size);
	}
	return 0;
}

/*
 * pci_mkbar
 *
 * Calculates BAR address is valid
 * Returns allocated address and updates next address
 * Returns zero if address is out of range
 */
static uint64_t
pci_mkbar(uint64_t *base, uint32_t size, uint64_t maxbase)
{
	uint64_t mask = size - 1;
	uint64_t cbase;

	if (*base + size >= maxbase)
		return (0);
	cbase = *base;
	*base = (*base + size + mask) & ~mask;
	return cbase;
}

/*
 * pci_add_bar
 *
 * Adds a BAR for the PCI device 'id'. On access, 'barfn' will be
 * called, and passed 'cookie' as an identifier.
 *
 * Parameters:
 *  id: PCI device to add the BAR to (local count, eg if id == 4,
 *      this BAR is to be added to the VM's 5th PCI device)
 *  type: type of the BAR to add (PCI_MAPREG_TYPE_xxx)
 *  size: Size of BAR area
 *  barfn: callback function invoked on BAR access
 *  cookie: cookie passed to barfn on access
 *
 * Returns 0 if the BAR was added successfully, 1 otherwise.
 */
int
pci_add_bar(uint8_t id, uint32_t type, uint32_t size, void *barfn, void *cookie)
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
	if (type == (PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_64BIT)) {
		base = pci_mkbar(&pci.pci_next_mmio_bar, size, VMM_PCI_MMIO_BAR_END);
		if (base == 0)
			return (1);

		pci.pci_devices[id].pd_cfg_space[bar_reg_idx] =
		    PCI_MAPREG_MEM_ADDR(base) | PCI_MAPREG_MEM_TYPE_64BIT;
		pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
		pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;
		pci.pci_devices[id].pd_bartype[bar_ct] = PCI_BAR_TYPE_MMIO;
		pci.pci_devices[id].pd_barsize[bar_ct] = size;
		pci.pci_devices[id].pd_bartype[bar_ct+1] = PCI_BAR_TYPE_MMIO;
		pci.pci_devices[id].pd_barsize[bar_ct+1] = 0;
		pci.pci_devices[id].pd_bar_ct+=2;
	} else if (type == PCI_MAPREG_TYPE_MEM) {
		base = pci_mkbar(&pci.pci_next_mmio_bar, size, VMM_PCI_MMIO_BAR_END);
		if (base == 0)
			return (1);

		pci.pci_devices[id].pd_cfg_space[bar_reg_idx] =
		    PCI_MAPREG_MEM_ADDR(base);
		pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
		pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;
		pci.pci_devices[id].pd_bartype[bar_ct] = PCI_BAR_TYPE_MMIO;
		pci.pci_devices[id].pd_barsize[bar_ct] = size;
		pci.pci_devices[id].pd_bar_ct++;
	} else if (type == PCI_MAPREG_TYPE_IO) {
		base = pci_mkbar(&pci.pci_next_io_bar, size, VMM_PCI_IO_BAR_END);
		if (base == 0)
			return (1);

		pci.pci_devices[id].pd_cfg_space[bar_reg_idx] =
		    PCI_MAPREG_IO_ADDR(base) |
		    PCI_MAPREG_TYPE_IO;
		pci.pci_devices[id].pd_barfunc[bar_ct] = barfn;
		pci.pci_devices[id].pd_bar_cookie[bar_ct] = cookie;
		pci.pci_devices[id].pd_bartype[bar_ct] = PCI_BAR_TYPE_IO;
		pci.pci_devices[id].pd_barsize[bar_ct] = size;
		pci.pci_devices[id].pd_bar_ct++;
	}

	log_warnx("%s: PCI_ADDBAR(%d, %d, %x, %x)", __progname,
		bar_ct, type, pci.pci_devices[id].pd_cfg_space[bar_reg_idx], size);

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
	log_warnx("%s: add_pci: %x.%x.%x", __progname, vid, pid, class);

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
	pci.pci_devices[*id].pd_ptd.id = 0xff;

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

void pci_add_pthru(struct vmd_vm *, int, int, int);

#define PCIOCUNBIND	_IOWR('p', 9, struct pcisel)

int ppt_csfn(int, uint8_t, uint8_t, uint32_t *, void *);
int ppt_iobar(int, uint16_t, uint32_t *, uint8_t *, void *, uint8_t);
int ppt_mmiobar(int, uint32_t, uint32_t *);

/* Only certain PCI values are writeable and most are already cached
 * 00h vendor   : ro
 * 02h device   : ro
 * 04h command  : rw
 * 06h status   : rw
 * 08h revision : ro
 * 09h class    : ro
 * 0ah subclass : ro
 * 0bh interface: ro
 * 0ch
 * 0dh
 * 0eh hdr type : ro
 * 0fh
 * 10h bar      : rw
 * 14h bar      : rw
 * 18h bar      : rw
 * 1ch bar      : rw
 * 20h bar      : rw
 * 24h bar      : rw
 */
int
ppt_csfn(int dir, uint8_t reg, uint8_t sz, uint32_t *data, void *cookie)
{
	struct pci_ptd *pd = cookie;
	struct pci_dev *pdev;

	pdev = &pci.pci_devices[pd->id];
	fprintf(stderr, "@pciio: %c:%.2x %d %.8x\n", dir == VEI_DIR_IN ? 'r' : 'w', reg, sz, *data);
	return 0;
}

/* Callback for I/O ports. Map to new I/O port and do it */
int
ppt_iobar(int dir, uint16_t reg, uint32_t *data, uint8_t *intr, void *cookie, uint8_t size)
{
	uint8_t barid = PTD_BAR(cookie);
	uint8_t devid = PTD_DEV(cookie);
	int hp, gp;

	*intr = 0xFF;
	remap_io(devid, barid, reg, &hp, &gp);
	do_pio(1, dir, hp, size, data);
	return 0;
}

int
ppt_mmiobar(int dir, uint32_t ofs, uint32_t *data)
{
	fprintf(stderr,"mmiobar: %d.%x\n", dir, ofs);
	return 0;
}

void
dump(void *ptr, int len)
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

/*
 * Add Passthrough PCI device to VMM PCI table
 */
void
pci_add_pthru(struct vmd_vm *vm, int bus, int dev, int fun)
{
	struct pci_ptd *pd;
	struct vm_barinfo bif;
	uint32_t id_reg, subid_reg, class_reg, cmd_reg, intr_reg;
	int i, rc;

	/* Read physical PCI config space */
	id_reg = ptd_conf_read(bus, dev, fun, PCI_ID_REG);
	if (PCI_VENDOR(id_reg) == PCI_VENDOR_INVALID || PCI_VENDOR(id_reg) == 0x0000) {
		fprintf(stderr, "Error: No PCI device @ %u:%u:%u\n", bus, dev, fun);
		return;
	}
	subid_reg = ptd_conf_read(bus, dev, fun, PCI_SUBSYS_ID_REG);
	class_reg = ptd_conf_read(bus, dev, fun, PCI_CLASS_REG);
	cmd_reg = ptd_conf_read(bus, dev, fun, PCI_COMMAND_STATUS_REG);
	intr_reg = ptd_conf_read(bus, dev, fun, PCI_INTERRUPT_REG);

	fprintf(stderr, "intr: pin:%.2x line:%.2x\n",
		PCI_INTERRUPT_PIN(intr_reg), PCI_INTERRUPT_LINE(intr_reg));
	ptd_conf_write(bus, dev, fun, 0x4, cmd_reg & ~(PCI_COMMAND_IO_ENABLE|PCI_COMMAND_MEM_ENABLE));
#if 0
	/* Unregister previous VMM */
	for (i = 0; i < MAXBAR; i++) {
		if (pd->barinfo[i].va) {
			unmapbar(pd->barinfo[i].va, pd->barinfo[i].size);
		}
	}
#endif
	pd = &ptd;
	pd->bus = bus;
	pd->dev = dev;
	pd->fun = fun;
	pci_add_device(&pd->id, PCI_VENDOR(id_reg), PCI_PRODUCT(id_reg),
			PCI_CLASS(class_reg), PCI_SUBCLASS(class_reg),
			PCI_VENDOR(subid_reg), PCI_PRODUCT(subid_reg),
			1, NULL, NULL);
	/* Cache full class register */
	_pcicfgwr32(pd->id, PCI_CLASS_REG, class_reg);

	/* Get BARs of native device */
	bif.seg = 0;
	bif.bus = bus;
	bif.dev = dev;
	bif.func = fun;
	rc = ioctl(env->vmd_fd, VMM_IOC_BARINFO,  &bif);
	if (rc != 0) {
		fprintf(stderr, "%d:%d:%d not valid pci device\n", bus, dev, fun);
		return;
	}
	for (i = 0; i < MAXBAR; i++) {
		int type;

		type = bif.bars[i].type;
		pd->barinfo[i].type = bif.bars[i].type;
		pd->barinfo[i].size = bif.bars[i].size;
		pd->barinfo[i].addr = bif.bars[i].addr;

		fprintf(stderr," Bar%d: type:%x base:%llx size:%x\n",
			i, pd->barinfo[i].type, pd->barinfo[i].addr, pd->barinfo[i].size);
		if (!pd->barinfo[i].size) {
			/* Kick bar index */
			pci.pci_devices[pd->id].pd_bar_ct++;
		}
		else if (PCI_MAPREG_TYPE(type) == PCI_MAPREG_TYPE_MEM) {
			pci_add_bar(pd->id, type, pd->barinfo[i].size, 
				    ppt_mmiobar, PTD_DEVID(pd->id, i));
			pd->barinfo[i].va = mapbar(i, pd->barinfo[i].addr, pd->barinfo[i].size);
			if (type == (PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_64BIT))
				i++;
		}
		else if (PCI_MAPREG_TYPE(type) == PCI_MAPREG_TYPE_IO) {
			/* This will get callback via pci_handle_io */
			pci_add_bar(pd->id, PCI_MAPREG_TYPE_IO,  pd->barinfo[i].size, 
				    ppt_iobar, PTD_DEVID(pd->id, i));
		}
	}
	showremap(pd);	
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
			if (pci.pci_devices[i].pd_bartype[j] != PCI_BAR_TYPE_IO)
				continue;
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
	uint32_t data, barval, barsize, bartype;
	uint64_t wrdata;
	int ret;
	pci_cs_fn_t csfunc;
	struct pci_ptd *pd;

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
	
	pd = &ptd;
	if ((o == 0x04 || o == 0x08 || o == 0x34 || o >= 0x40) && (pd->id == d)) {
		/* Passthrough PCI Cfg Space */
		if (vei->vei.vei_dir == VEI_DIR_IN) {
			data = ptd_conf_read(pd->bus, pd->dev, pd->fun, o);
			_pcicfgwr32(d, o, data);
		}
		else {
			data = vei->vei.vei_data;
			ptd_conf_write(pd->bus, pd->dev, pd->fun, o, data);
		}
	}

	wrdata = vei->vei.vei_data;
	data = 0;
	if (d < pci.pci_dev_ct && !b && !f) {
		data = _pcicfgrd32(d, o);
	}
	
	csfunc = pci.pci_devices[d].pd_csfunc;
	if (csfunc != NULL) {
		ret = csfunc(vei->vei.vei_dir, o, sz, &vei->vei.vei_data, pci.pci_devices[d].pd_cookie);
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
	if (vei->vei.vei_dir == VEI_DIR_OUT) {
		if (o >= 0x10 && o <= 0x24) {
			/* When Changing a BAR we must calculate readonly bits */
			baridx = (o - 0x10) / 4;
			barval = pci.pci_devices[d].pd_cfg_space[o/4];
			barsize = pci.pci_devices[d].pd_barsize[baridx];
			bartype = pci.pci_devices[d].pd_bartype[baridx];

			/* Mask off size */
			vei->vei.vei_data &= ~(barsize - 1);

			/* Keep lower bits of current config space value */
			if (bartype == PCI_BAR_TYPE_IO)
				vei->vei.vei_data |= (barval & ~PCI_MAPREG_IO_ADDR_MASK);
			else {
				vei->vei.vei_data |= (barval & ~PCI_MAPREG_MEM_ADDR_MASK);
				unregister_mem(barval & PCI_MAPREG_MEM_ADDR_MASK);
				register_mem(vei->vei.vei_data & PCI_MAPREG_MEM_ADDR_MASK,
				    barsize, pci_memh2, PTD_DEVID(d, baridx));	
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
