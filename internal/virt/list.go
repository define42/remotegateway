package virt

import (
	"fmt"
	"log"
	"strings"

	"libvirt.org/go/libvirt"
)

type vmInfo struct {
	Name      string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
}

func ListVMs(prefix string) ([]vmInfo, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		log.Printf("list vms connect: %v", err)
		return nil, err
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(0)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer func() {
		for _, d := range doms {
			_ = d.Free()
		}
	}()

	var result []vmInfo
	for _, d := range doms {
		name, err := d.GetName()
		if err != nil {
			log.Printf("domain name: %v", err)
			continue
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}

		state, _, err := d.GetState()
		if err != nil {
			log.Printf("domain state %s: %v", name, err)
			continue
		}
		mem, vcpu := domainResources(d)
		volGB := domainDiskGB(d)
		result = append(result, vmInfo{Name: name, State: formatState(state), MemoryMiB: mem, VCPU: vcpu, VolumeGB: volGB})
	}
	return result, nil
}

func domainResources(d libvirt.Domain) (int, int) {
	info, err := d.GetInfo()
	if err != nil {
		log.Printf("domain info: %v", err)
		return 0, 0
	}
	memMiB := int(info.Memory / 1024)
	return memMiB, int(info.NrVirtCpu)
}

func domainDiskGB(d libvirt.Domain) int {
	info, err := d.GetBlockInfo("vda", 0)
	if err != nil {
		log.Printf("block info: %v", err)
		return 0
	}
	size := info.Capacity
	if size == 0 {
		size = info.Physical
	}
	if size == 0 {
		size = info.Allocation
	}
	if size == 0 {
		return 0
	}
	return int((size + (1 << 30) - 1) >> 30)
}

func formatState(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_RUNNING:
		return "running"
	case libvirt.DOMAIN_PAUSED:
		return "paused"
	case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF:
		return "shut off"
	case libvirt.DOMAIN_CRASHED:
		return "crashed"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "suspended"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}
