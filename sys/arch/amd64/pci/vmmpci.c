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

struct vmmpci_softc {
	struct device 		sc_dev;
	void			*sc_ih;

	int			sc_domain;
	pci_chipset_tag_t	sc_pc;
	pcitag_t		sc_tag;

	uint32_t      		pending;		// pending interrupt count
};

struct vmmpci_dev {
	struct device	       *vp_dev;
	int			vp_domain;
	pci_chipset_tag_t	vp_pc;
	pcitag_t		vp_tag;
};

int	vmmpci_match(struct device *, void *, void *);
void	vmmpci_attach(struct device *, struct device *, void *);
void	vmmpci_callback(struct device *);
int	vmmpci_print(void *, const char *);
int 	vmmpci_find(pci_chipset_tag_t pc, pcitag_t tag);
int 	vmmpci_add(pci_chipset_tag_t pc, pcitag_t tag);
int 	vmmpci_intr(void *arg);

struct cfattach vmmpci_ca = {
	sizeof(struct vmmpci_softc), vmmpci_match, vmmpci_attach
};

struct cfdriver vmmpci_cd = {
	NULL, "vmmpci", DV_DULL
};

#define MAXVMMPCI 4

struct vmmpci_dev vmmpcis[MAXVMMPCI];

int
vmmpci_intr(void *arg)
{
	struct vmmpci_softc *sc = arg;

	sc->pending++;
	return 1;
}

int
vmmpci_find(pci_chipset_tag_t pc, pcitag_t tag)
{
	int i;

	for (i = 0; i < MAXVMMPCI; i++) {
		if (vmmpcis[i].vp_dev &&
		    vmmpcis[i].vp_pc == pc && 
		    vmmpcis[i].vp_tag == tag)
			return (1);
	}
	return (0);
}

int
vmmpci_add(pci_chipset_tag_t pc, pcitag_t tag)
{
	int i;
	struct device *pd;
	struct pci_softc *psc;

	/* Check if we are already mapped */
	if (vmmpci_find(pc, tag))
		return (1);

	for (i = 0; i < MAXVMMPCI; i++) {
		if (vmmpcis[i].vp_dev == 0) {
			/* Find parent device */
			pd = (struct device *)pci_find_bytag(0, tag);
			if (pd == NULL)
				return (0);
			psc = (struct pci_softc *)pd->dv_parent;

			vmmpcis[i].vp_dev = pd;
			vmmpcis[i].vp_pc = pc;
			vmmpcis[i].vp_tag = tag;

			/* detach the old device, reattach */
			config_detach(pd, 0);
			pci_probe_device(psc, tag, NULL, NULL);
			return (1);
		}
	}
	return (0);
}

int
vmmpci_pending(pcitag_t tag, uint32_t *pending)
{
	struct vmmpci_softc *sc;

	/* Are we mapped? */	
	if (!vmmpci_find(NULL, tag))
		return (0);
	sc = (struct vmmpci_softc *)pci_find_bytag(0, tag);
	if (sc == NULL)
		return (0);
	*pending = sc->pending;
	return (1);		
}

int
vmmpci_match(struct device *parent, void *match, void *aux)
{
	struct pci_attach_args *pa = aux;
	int rc;

	rc = vmmpci_find(pa->pa_pc, pa->pa_tag);
	if (rc)
		return (100);
	return (0);
}

void
vmmpci_attach(struct device *parent, struct device *self, void *aux)
{
	struct vmmpci_softc 	*sc = (struct vmmpci_softc *)self;
	struct pci_attach_args 	*pa = aux;
	pci_chipset_tag_t	pc  = pa->pa_pc;
	pci_intr_handle_t	ih;

	sc->sc_pc  = pc;
	sc->sc_tag = pa->pa_tag;

	/* Map our interrupt */
	if (pci_intr_map_msi(pa, &ih) || pci_intr_map(pa, &ih)) {
		printf(": couldn't map interrupt\n");
		return;
	}
	sc->sc_ih = pci_intr_establish(pc, ih, IPL_BIO, vmmpci_intr, 
			sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": couldn't establish interrupt");
		return;
	}
}
