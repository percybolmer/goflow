package goflow

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
	"time"
)

// Pcap is a struct used to ease the usage of PCAP writing and Readign PCAPs
// Contains the Original file, the pcapgo Writer and more stuff realted to the PCAP
type Pcap struct {
	File *os.File
	Writer *pcapgo.Writer
}

// Close will close the original file behind the PCAP, starting a chain reaction that closes the Writer aswell
func (p *Pcap) Close() {
	p.File.Close()
}

// NewPcap will create a New Pcap file at given Path
// A Pcap header will be written by default with default Values
// If you want to change Snapshot Length and LinkType Please see NewCustomPcap
func NewPcap(path string) (*Pcap, error){
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	// a Pcap header has to be written to the file
	p := &Pcap{
		File:   f,
		Writer: pcapgo.NewWriter(f),
	}
	return p, p.Writer.WriteFileHeader(defaultSnapshotLength, defaultLinkTypeLayer)
}
// WritePacket writes a packet to the related Pcap File
func (p *Pcap) WritePacket(layers ...gopacket.SerializableLayer) error{
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}

	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return err
	}
	packetLength := len(buf.Bytes())
	dateTime := time.Now()
	// Fill meta information for packet for pcap
	cInfo := gopacket.CaptureInfo{
		// Timestamp is the time the packet was captured, if that is known.
		Timestamp: dateTime,
		// CaptureLength is the total number of bytes read off of the wire.
		CaptureLength: packetLength,
		// Length is the size of the original packet.  Should always be >=
		// CaptureLength.
		Length: packetLength,
		// InterfaceIndex, we do not need it
		InterfaceIndex: 0,
	}

	return p.Writer.WritePacket(cInfo, buf.Bytes())

}

// ReadPcap reads a pcap and prints all packets
// argument can be a filter to onlly take certain packets
func ReadPcap(path string, bpf string) (*gopacket.PacketSource,error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	//defer handle.Close()

	// apply filter if not empty
	if bpf != "" {
		// error checking ?? in teh future
		err = handle.SetBPFFilter(bpf)
		if err != nil {
			return nil, err
		}
	}

	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}