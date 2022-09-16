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
	GetDeviceWithName(string) (*DetailPCIAddr, error)
	GetNameWithDetails(*DetailPCIAddr) string
	ReserveDeviceWithName(string) error
	ReserveDevice() (string, error)
	FreeDevice(dev string) error
}

type DetailPCIAddr struct {
	pciDomain string
	pciBus    string
	pciSlot   string
	pciFunc   string
}

type NFDevice struct {
	pciAddr   string
	pciDetail DetailPCIAddr
	reserved  bool
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
		if !d.devices[i].reserved && d.devices[i].pciAddr != "" {
			d.devices[i].reserved = true
			return d.devices[i].pciAddr, nil
		}
	}
	return "", errors.New("no available device found")
}

func (d *NFDeviceBase) ReserveDeviceWithName(dev string) error {
	for i := 0; i < len(d.devices); i++ {
		if !d.devices[i].reserved && d.devices[i].pciAddr == dev {
			d.devices[i].reserved = true
			return nil
		}
	}
	return nil
}

func (d *NFDeviceBase) GetDeviceWithName(dev string) (*DetailPCIAddr, error) {
	for i := 0; i < len(d.devices); i++ {
		if d.devices[i].reserved && d.devices[i].pciAddr == dev {
			return &d.devices[i].pciDetail, nil
		}
	}
	return nil, errors.New("no available device found")
}

func (d *NFDeviceBase) GetNameWithDetails(detailPciAddr *DetailPCIAddr) string {
	for i := 0; i < len(d.devices); i++ {
		if d.devices[i].pciDetail == *detailPciAddr {
			return d.devices[i].pciAddr
		}
	}
	return ""
}

func (d *NFDeviceBase) FreeDevice(dev string) error {
	for i := 0; i < len(d.devices); i++ {
		if d.devices[i].reserved && d.devices[i].pciAddr == dev {
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
			nfd.devices[count].pciAddr = convertToDPDKPCI(device.Address, count)
			nfd.devices[count].pciDetail.pciDomain = device.Address[0:4]
			nfd.devices[count].pciDetail.pciBus = device.Address[5:7]
			nfd.devices[count].pciDetail.pciSlot = device.Address[8:10]
			nfd.devices[count].pciDetail.pciFunc = device.Address[11:]
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
