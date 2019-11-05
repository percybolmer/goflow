package goflow

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strconv"
	"strings"
	"time"
)

var (

	// Default values
	defaultSnapshotLength uint32 = 65536
	defaultLinkTypeLayer layers.LinkType = layers.LinkTypeEthernet
	// Errors related to the package
	ErrNoDevicesFound      error = errors.New("no device that can sniff was found")
	ErrNoSuchDevice        error = errors.New("no device with the given name was found")
	ErrNoInterfaceSelected error = errors.New("no interface to sniff on was currently selected")
	ErrNotValidIPv4	error = errors.New("supplied string is not a valid IPv4 address")
)

// Goflow is used to control the flow of network data through out given handler, it can be a pcap or a network interface
type Goflow struct {
	// Interfaces that can be sniffed, found by running FindDevices
	Interfaces []pcap.Interface
	// selectedInterface is the currently used interface
	selectedInterface pcap.Interface
	// snapShotLength is a value used that will specify how big the pcap header is
	snapShotLength int32
	// promiscousMode
	promiscousMode bool
}



// Sniff will open a live capture on the selected interface,
// Will return a channel for the packets that are sent
func (n *Goflow) Sniff() (*gopacket.PacketSource, error) {
	// Open a live stream from the currently selectedInterface
	if n.selectedInterface.Name == "" {
		return nil, ErrNoInterfaceSelected
	}
	if n.snapShotLength == 0 {
		n.snapShotLength = int32(defaultSnapshotLength)
	}
	// Start processing our packets
	handle, err := pcap.OpenLive(n.selectedInterface.Name, n.snapShotLength, n.promiscousMode, 30*time.Second)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", n.selectedInterface.Name, err)
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}

// SetInterface will parse and find all possible interfaces that the Goflow package has the right to use
// and it will set the given one as the Interface to use.
// Will return an error if the given device is not found amoung the useable devices
func (n *Goflow) SetInterface(interfaceName string) error {
	err := n.FindDevices()
	if err != nil {
		return err
	}

	for _, in := range n.Interfaces {
		if in.Name == interfaceName {
			n.selectedInterface = in
		}
	}
	if n.selectedInterface.Name != interfaceName {
		return ErrNoSuchDevice
	}
	return nil
}

// @TODO add NewCustomPcap function that accepts snapshot length and Layers
// FindDevices prints all network interface info
func (n *Goflow) FindDevices() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for _, device := range devices {
		if len(device.Addresses) != 0 {
			// Make sure its a PROPER Sniffing Device, Dismiss LOopback and Virtual interfaces
			if device.Name == "lo" || strings.Contains(device.Name, "virb") {
				continue
			}
		}
		n.Interfaces = append(n.Interfaces, device)
	}
	if len(devices) == 0 {
		return ErrNoDevicesFound
	}
	return nil
}
// SpoofEthernetLayer will create a fake ethernetlayer containing the given
// src and dst mac address, will return error if the provided
// strings are not proper Mac addresses
func SpoofEthernetLayer(srcMac, dstMac string) (*layers.Ethernet,error){
	src, err := net.ParseMAC(srcMac)
	if err != nil {
		return nil, err
	}
	dst, err := net.ParseMAC(dstMac)
	if err != nil {
		return nil, err
	}

	ethernetLayer := &layers.Ethernet{
		SrcMAC: src,
		DstMAC: dst,
	}
	ethernetLayer.EthernetType = layers.EthernetTypeIPv4
	return ethernetLayer,nil
}
// SpoofTCPLayer is used to create a bogus TCP Layer containing the src,dst port.
// Remeber that payload length has to be set to properly forge the packet
func SpoofTCPLayer(srcPort, dstPort, payloadLength uint16) *layers.TCP{
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		PSH:        true,
		Window:     payloadLength,
		DataOffset: 0,
	}
}
// SpoofIPV4Layer will create a fake ethernet Layer containing the Given src and dst IP addresses
// If the given strings are not proper IP it will return error
// protocol should be the protocol that is the next in line
func SpoofIPV4Layer(srcIP, dstIP string, protocol layers.IPProtocol) (*layers.IPv4, error){
	if !is_ipv4(srcIP) || !is_ipv4(dstIP){
		return nil, ErrNotValidIPv4
	}
	sourceIP := net.ParseIP(srcIP)
	destIP := net.ParseIP(dstIP)
	ipv4 := &layers.IPv4{
		Version: 4,
		SrcIP:   sourceIP,
		DstIP:   destIP,
		TTL:     128,
	}
	ipv4.Protocol = protocol
	return ipv4, nil


}
// is_ipv4 will validate if a string is really a valid IP
func is_ipv4(host string) bool {
	parts := strings.Split(host, ".")

	if len(parts) < 4 {
		return false
	}

	for _,x := range parts {
		if i, err := strconv.Atoi(x); err == nil {
			if i < 0 || i > 255 {
				return false
			}
		} else {
			return false
		}

	}
	return true
}