/*	$OpenBSD: pcib.c,v 1.6 2013/05/30 16:15:01 deraadt Exp $	*/
/*	$NetBSD: pcib.c,v 1.6 1997/06/06 23:29:16 thorpej Exp $	*/

/*-
 * Copyright (c) 1996 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>

#include <machine/bus.h>
#include <dev/isa/isavar.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <dev/pci/pcidevs.h>

#include <machine/vmmvar.h>

int	vmmpcimatch(struct device *, void *, void *);
void	vmmpciattach(struct device *, struct device *, void *);
void	vmmpci_callback(struct device *);
int	vmmpci_print(void *, const char *);

struct cfattach vmmpci_ca = {
	sizeof(struct device), vmmpcimatch, vmmpciattach
};

struct cfdriver vmmpci_cd = {
	NULL, "vmmpci", DV_DULL
};

#define MAXVMMPCI 4

struct vmmpcidev {
	int		  vp_valid;
	pci_chipset_tag_t vp_pc;
	pcitag_t	  vp_tag;
} vmmpcis[MAXVMMPCI];

int vmmpcifind(pci_chipset_tag_t pc, pcitag_t tag);
int vmmpciadd(pci_chipset_tag_t pc, pcitag_t tag);

int
vmmpcifind(pci_chipset_tag_t pc, pcitag_t tag)
{
	int i;

	for (i = 0; i < MAXVMMPCI; i++) {
		if (vmmpcis[i].vp_valid && (vmmpcis[i].vp_pc == pc) && 
		    (vmmpcis[i].vp_tag == tag))
			return (1);
	}
	return (0);
}

int
vmmpciadd(pci_chipset_tag_t pc, pcitag_t tag)
{
	int i;
	pcireg_t reg;

	if (vmmpcifind(pc, tag))
		return (1);
	/* Check if we exist first */
	reg = pci_conf_read(pc, tag, PCI_ID_REG);
	if (PCI_VENDOR(reg) == PCI_VENDOR_INVALID)
		return (0);
	if (PCI_VENDOR(reg) == 0)
		return (0);
	for (i = 0; i < MAXVMMPCI; i++) {
		if (vmmpcis[i].vp_valid == 0) {
			vmmpcis[i].vp_valid = 1;
			vmmpcis[i].vp_pc = pc;
			vmmpcis[i].vp_tag = tag;

			/* detach the old device, reattach */
			return (1);
		}
	}
	return (0);
}

int
vmmpcimatch(struct device *parent, void *match, void *aux)
{
	struct pci_attach_args *pa = aux;
	int rc;

	rc = vmmpcifind(pa->pa_pc, pa->pa_tag);
	printf("PCI Attach VMM: %d.%d.%d = %d\n", pa->pa_bus, pa->pa_device, pa->pa_function, rc);
	if (rc)
		return (100);
	return (0);
}

void
vmmpciattach(struct device *parent, struct device *self, void *aux)
{
	/*
	 * Cannot attach isa bus now; must postpone for various reasons
	 */
	printf("vmmpci attach \n");
}
