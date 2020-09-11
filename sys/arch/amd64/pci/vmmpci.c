/*	$OpenBSD: pcib.c,v 1.6 2013/05/30 16:15:01 deraadt Exp $	*/
/*	$NetBSD: pcib.c,v 1.6 1997/06/06 23:29:16 thorpej Exp $	*/

/*-
 * Copyright (c) 1996 Jordan Hargrave<jordan_hargrave@hotmail.com>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>

#include <machine/bus.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <dev/pci/pcidevs.h>

#include <machine/vmmvar.h>
#include <machine/vmmpci.h>

struct vmmpci_softc {
	struct device 		sc_dev;
	void			*sc_ih;

	int			sc_domain;
	pci_chipset_tag_t	sc_pc;
	pcitag_t		sc_tag;

	uint32_t      		pending;		// pending interrupt count
};

#define VP_VALID	0x80000000

/* Keep track of registered devices */
struct vmmpci_dev {
	int			vp_flags;
	int			vp_domain;
	pcitag_t		vp_tag;
};

int	vmmpci_match(struct device *, void *, void *);
void	vmmpci_attach(struct device *, struct device *, void *);
void	vmmpci_callback(struct device *);
int	vmmpci_print(void *, const char *);
int 	vmmpci_intr(void *arg);

struct cfattach vmmpci_ca = {
	sizeof(struct vmmpci_softc), vmmpci_match, vmmpci_attach
};

struct cfdriver vmmpci_cd = {
	NULL, "vmmpci", DV_DULL
};

#define MAXVMMPCI 4

struct vmmpci_dev vmmpcis[MAXVMMPCI];

/* Interrupt handler. Increase pending count for ioctl.  TODO:better method? */
int
vmmpci_intr(void *arg)
{
	struct vmmpci_softc *sc = arg;

	sc->pending++;
	return 1;
}

/* Get number of pending interrupts for a device */
int
vmmpci_pending(int domain, pcitag_t tag, uint32_t *pending)
{
	struct vmmpci_softc *sc;

	/* Are we mapped? */	
	if (!vmmpci_find(domain, tag))
		return (0);

	/* If we are mapped, the device should be a VMMPCI */
	sc = (struct vmmpci_softc *)pci_find_bytag(domain, tag);
	if (sc == NULL)
		return (0);

	/* Return current pending count */
	*pending = sc->pending;
	return (1);		
}

/* Check if this PCI device has been registered */
int
vmmpci_find(int domain, pcitag_t tag)
{
	int i;

	for (i = 0; i < MAXVMMPCI; i++) {
		if ((vmmpcis[i].vp_flags & VP_VALID) &&
		    vmmpcis[i].vp_domain == domain &&
		    vmmpcis[i].vp_tag == tag)
			return (1);
	}
	return (0);
}

/* Add a PCI device to valid passthrough list and reprobe */
int
vmmpci_add(int domain, pcitag_t tag, int flags)
{
	struct pci_softc *psc;
	struct device *pd;
	int i;

	/* Check if we are already mapped */
	if (vmmpci_find(domain, tag))
		return (1);

	for (i = 0; i < MAXVMMPCI; i++) {
		if ((vmmpcis[i].vp_flags & VP_VALID) == 0) {
			/* Find parent device */
			pd = (struct device *)pci_find_bytag(domain, tag);
			if (pd == NULL)
				return (0);

			vmmpcis[i].vp_domain = domain;
			vmmpcis[i].vp_tag = tag;
			vmmpcis[i].vp_flags = VP_VALID | flags;

			/* detach the old device, reattach */
			psc = (struct pci_softc *)pd->dv_parent;
			config_detach(pd, 0);

			pci_probe_device(psc, tag, NULL, NULL);
			return (1);
		}
	}
	return (0);
}

int
vmmpci_match(struct device *parent, void *match, void *aux)
{
	struct pci_attach_args *pa = aux;
	int rc;

	/* Check if device is registered, claim it */
	rc = vmmpci_find(pa->pa_domain, pa->pa_tag);
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

	/* Map our interrupt (TODO: what about devices with no interrupt?) */
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
