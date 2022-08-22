package controllers

import (
	"errors"
	"strconv"
	"strings"

	"github.com/jaypipes/ghw"
)

const (
	maxNumOfDevices  = 32
	mellanoxDeviceID = "15b3"
)

type DeviceAllocator interface {
	ReserveDevice() (string, error)
	FreeDevice(dev string) error
}

type NFDevice struct {
	pci_addr string
	reserved bool
}

type NFDeviceBase struct {
	devices [maxNumOfDevices]NFDevice
}

func NewNFDeviceBase() (*NFDeviceBase, error) {
	nfd := NFDeviceBase{}
	if err := fillDeviceList(&nfd); err != nil {
		return nil, err
	}
	return &nfd, nil
}

func (d *NFDeviceBase) ReserveDevice() (string, error) {
	for i := 0; i < len(d.devices); i++ {
		if !d.devices[i].reserved && d.devices[i].pci_addr != "" {
			d.devices[i].reserved = true
			return d.devices[i].pci_addr, nil
		}
	}
	return "", errors.New("no available device found")
}

func (d *NFDeviceBase) FreeDevice(dev string) error {
	for i := 0; i < len(d.devices); i++ {
		if d.devices[i].reserved && d.devices[i].pci_addr == dev {
			d.devices[i].reserved = false
			return nil
		}
	}
	return errors.New("device not found")
}

func fillDeviceList(nfd *NFDeviceBase) error {
	var count int
	pci, err := ghw.PCI()
	if err != nil {
		return err
	}

	for _, device := range pci.Devices {
		if (device.Vendor.ID == mellanoxDeviceID) && strings.Contains(device.Product.Name, "Virtual") {
			if count >= maxNumOfDevices {
				return errors.New("num of devices exceeds max possible")
			}
			nfd.devices[count].pci_addr = convertToDPDKPCI(device.Address, count)
			nfd.devices[count].reserved = false
			count += 1
		}
	}
	return nil
}

func convertToDPDKPCI(pci string, idx int) string {
	temp := []rune(pci)
	temp[len(pci)-1] = '0'
	res_pci := string(temp)
	res_pci += "_representor_vf"
	res_pci += strconv.Itoa(idx)
	return res_pci
}
