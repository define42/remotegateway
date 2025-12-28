package virt

import (
	"fmt"
	"io"
	"log"
	"os"
	"remotegateway/internal/qemu_domain"

	"libvirt.org/go/libvirt"
)

// startVM starts a libvirt VM by name if it is not already running

func StartVM(name string) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return err
	}
	defer conn.Close()

	dom, err := conn.DomainDefineXML(qemu_domain.UbuntuDomain(name))
	if err != nil {
		fmt.Println("whaat", err)
		return err
	}
	defer func() {
		_ = dom.Free()
	}()

	if err := dom.Create(); err != nil {
		return err
	}

	//fmt.Printf("VM %s started (ID %d)\n", name, dom.GetID())
	return nil

}

func CopyAndResizeVolume(
	conn *libvirt.Connect,
	poolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {

	// Lookup storage pool
	pool, err := conn.LookupStoragePoolByName(poolName)
	if err != nil {
		return fmt.Errorf("lookup pool: %w", err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// Create volume XML
	volXML := fmt.Sprintf(`
<volume>
  <name>%s</name>
  <capacity unit="bytes">%d</capacity>
  <target>
    <format type="qcow2"/>
  </target>
</volume>`, volumeName, capacityBytes)

	// Create volume
	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return fmt.Errorf("create volume: %w", err)
	}
	defer func() {
		_ = vol.Free()
	}()

	// Open source image
	src, err := os.Open(sourceImagePath)
	if err != nil {
		return fmt.Errorf("open source image: %w", err)
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat source image: %w", err)
	}

	// Create libvirt stream
	stream, err := conn.NewStream(0)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	defer func() {
		_ = stream.Free()
	}()

	// Start upload
	if err := vol.Upload(stream, 0, uint64(srcInfo.Size()), 0); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}

	if err := stream.SendAll(func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		if nbytes <= 0 {
			return []byte{}, nil
		}
		buf := make([]byte, nbytes)
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				if n == 0 {
					return []byte{}, nil
				}
				return buf[:n], nil
			}
			return nil, err
		}
		if n == 0 {
			return []byte{}, nil
		}
		return buf[:n], nil
	}); err != nil {
		_ = stream.Abort()
		return fmt.Errorf("stream send: %w", err)
	}

	if err := stream.Finish(); err != nil {
		return fmt.Errorf("stream finish: %w", err)
	}

	if capacityBytes > 0 {
		volInfo, err := vol.GetInfo()
		if err != nil {
			return fmt.Errorf("get volume info: %w", err)
		}
		if volInfo.Capacity < capacityBytes {
			if err := vol.Resize(capacityBytes, 0); err != nil {
				return fmt.Errorf("resize volume: %w", err)
			}
		}
	}

	return nil
}

func DestroyExistingDomain(conn *libvirt.Connect, vmName string) error {
	existingDom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil
	}
	defer func() {
		_ = existingDom.Free()
	}()

	active, err := existingDom.IsActive()
	if err != nil {
		return err
	}
	if active {
		if err := existingDom.Destroy(); err != nil {
			return err
		}
		log.Printf("Destroyed running domain %s", vmName)
	}

	if err := existingDom.Undefine(); err != nil {
		return err
	}
	log.Printf("Undefined domain %s", vmName)
	return nil
}
