package layers

import "github.com/google/gopacket"

// CustomLayer Create a custom layer
type CustomLayer struct {
	//Example layer with 2 bytes in a row
	SomeByte    byte
	AnotherByte byte
	restOfData  []byte
}

// CustomLayerType Register the layertype so that we can use it
// the first value is the ID (should be unique, 2000+ or negativ)
var CustomLayerType = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		Name:    "CustomLayerType",
		Decoder: gopacket.DecodeFunc(decodeCustomLayer),
	},
)

// LayerType When people aquire the layertype, what should it return?
// we want to return our customLayer ofc
func (l CustomLayer) LayerType() gopacket.LayerType {
	return CustomLayerType
}

// LayerContents returns the layers information
// as this instance we return header data
func (l CustomLayer) LayerContents() []byte {
	return []byte{l.SomeByte, l.AnotherByte}
}

// LayerPayload is used to return the layers payload
// So we want to return our payload byte array
func (l CustomLayer) LayerPayload() []byte {
	return l.restOfData
}

// Custom decodeing function that we can name whatver but it needs the same parametesrs + return
// This function can be used when registering the layer
func decodeCustomLayer(data []byte, p gopacket.PacketBuilder) error {

	//Add layer appends the layer to the Layerlist
	// This is where the decoding is done
	// Assign the values to the Structs byte placeholders
	// etc in this examlpe we just pick byte 1 and 2 but for IPv4 etc pick the first 20 etcetc
	p.AddLayer(&CustomLayer{data[0], data[1], data[2:]})

	// The return value is what to expect for the rest of the Packet
	// Etc we can return a new layer or a payload
	// returning nil means its the last layer and that all decoding is done

	// Returning another layer tells it to decode the next layer
	// etc if its ethernet
	// return p.NextDecoder(layers.LayerTypeEthernet)

	// returning payload of raw bytes tells it to assign application layer by default
	return p.NextDecoder(gopacket.LayerTypePayload)
}