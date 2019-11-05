package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/percybolmer/goflow"
	l "github.com/percybolmer/goflow/layers"
)

func main() {

	n := goflow.Goflow{}
	err := n.SetInterface("wlp3s0")
	if err!= nil{
		panic(err)
	}

	spoofTcp()

	ps,err := goflow.ReadPcap("tcpSpoof.pcap", "")
	if err != nil {
		panic(err)
	}

	for packet := range ps.Packets(){
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("Found TCP Layer")
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.Payload != nil {
				exampleLayer := l.ExampleLayer{}
				err := exampleLayer.DecodeFromBytes(tcp.Payload)
				if err != nil {
					panic(err)
				}

				fmt.Println(string(exampleLayer.UserName))
				fmt.Println(string(exampleLayer.Object))
				fmt.Println(string(exampleLayer.RealIP))
				fmt.Println(string(exampleLayer.Payload))
			}
		}
	}


}

func spoofTcp() {
	f, err := goflow.NewPcap("tcpSpoof.pcap")
	defer f.Close()
	// Let's craft network packets
	ethernetLayer, err := goflow.SpoofEthernetLayer("BA:DB:00:BF:EE:D1", "DE:FA:CE:DB:AB:E1")
	if err != nil {
		panic(err)
	}

	ipv4, err := goflow.SpoofIPV4Layer("8.8.8.8", "218.108.149.150", layers.IPProtocolTCP)
	if err != nil {
		panic(err)
	}

	exLayer := l.ExampleLayer{
		UserName: []byte("Mr.Terrorist"),
		Object:   []byte("Steal_data"),
		RealIP:   []byte("172.168.0.1"),
		Payload:  []byte{1,2,3,4},
	}
	tcp := goflow.SpoofTCPLayer(443,80,uint16(len(exLayer.LayerContents())))
	// gopacket.Payload(payload)
	err = f.WritePacket(ethernetLayer, ipv4, tcp,exLayer)
	if err != nil {
		panic(err)
	}
}
