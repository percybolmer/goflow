package layers

import (
	"encoding/base64"
	"errors"
	"github.com/google/gopacket"
)

// ExampleLayer Create a custom layer
type ExampleLayer struct {
	//Username is 16 bytes
	UserName    []byte
	// Object is 16 bytes
	Object []byte
	// RealIP is 32 bytes
	RealIP []byte
	Payload  []byte
}

// ExampleLayer Register the layertype so that we can use it
// the first value is the ID (should be unique, 2000+ or negativ)
var ExampleLayerType = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		Name:    "ExampleLayerType",
		Decoder: gopacket.DecodeFunc(decodeExampleLayer),
	},
)

// LayerType When people aquire the layertype, what should it return?
// we want to return our ExampleLayer ofc
func (l ExampleLayer) LayerType() gopacket.LayerType {
	return ExampleLayerType
}

// LayerContents returns the layers information
// as this instance we return header data
func (l ExampleLayer) LayerContents() []byte {
	u := l.UserName
	o := l.Object

	var output []byte
	output = append(output, u...)
	output = append(output, o...)
	output = append(output, l.RealIP...)
	return output
}

// LayerPayload is used to return the layers payload
// So we want to return our payload byte array
func (l ExampleLayer) LayerPayload() []byte {
	return l.Payload
}
func (l ExampleLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	//length := len(l.UserName) + len(l.Object) + len(l.RealIP) + len(l.Payload)
	length := 64 + len(l.Payload)
	bytes, err := b.PrependBytes(length)
	if err != nil {
		return err
	}

	un := base64.StdEncoding.EncodeToString(l.UserName)
	obj := base64.StdEncoding.EncodeToString(l.Object)
	rip := base64.StdEncoding.EncodeToString(l.RealIP)
	copy(bytes[0:16], un)
	copy(bytes[16:32], obj)
	copy(bytes[32:48], rip)
	copy(bytes[48:], l.Payload)
	return nil
}
// Custom decodeing function that we can name whatver but it needs the same parametesrs + return
// This function can be used when registering the layer
func decodeExampleLayer(data []byte, p gopacket.PacketBuilder) error {

	//Add layer appends the layer to the Layerlist
	// This is where the decoding is done
	// Assign the values to the Structs byte placeholders
	// etc in this examlpe we just pick byte 1 and 2 but for IPv4 etc pick the first 20 etcetc
	l := &ExampleLayer{}
	err := l.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	p.AddLayer(l)

	// The return value is what to expect for the rest of the Packet
	// Etc we can return a new layer or a payload
	// returning nil means its the last layer and that all decoding is done

	// Returning another layer tells it to decode the next layer
	// etc if its ethernet
	// return p.NextDecoder(layers.LayerTypeEthernet)

	// returning payload of raw bytes tells it to assign application layer by default
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (l *ExampleLayer) DecodeFromBytes(data []byte) error {
	if len(data) < 10{
		return errors.New("Not enough data to decode examplelayer")
	}

	un,err  := base64.StdEncoding.DecodeString(string(data[0:16]))
	if err != nil {
		return err
	}
	obj,err  := base64.StdEncoding.DecodeString(string(data[16:32]))
	if err != nil {
		return err
	}
	rip,err  := base64.StdEncoding.DecodeString(string(data[32:48]))
	if err != nil {
		return err
	}

	l.UserName = un
	l.Object = obj
	l.RealIP = rip
	l.Payload = data[48:]
	return nil
}