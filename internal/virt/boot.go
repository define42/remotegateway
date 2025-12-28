package virt

import (
	"libvirt.org/go/libvirt"
)

// startVM starts a libvirt VM by name if it is not already running

func StartVM(name string) error {
	conn, err := libvirt.NewConnect(libvirtURI())
	if err != nil {
		return err
	}
	defer conn.Close()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return err
	}
	defer dom.Free()

	active, err := dom.IsActive()
	if err != nil {
		return err
	}
	if active {
		return nil
	}
	return dom.Create()
}
