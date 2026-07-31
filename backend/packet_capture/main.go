package main

import (
"fmt"
"log"
"time"

"github.com/google/gopacket"
"github.com/google/gopacket/layers"
"github.com/google/gopacket/pcap"
)

func main() {
fmt.Println("🛡️  Advanced IDS - Packet Sniffer")
fmt.Println("==================================")

devices, err := pcap.FindAllDevs()
if err != nil {
log.Fatal("Error finding devices:", err)
}

if len(devices) == 0 {
log.Fatal("No network devices found!")
}

device := devices[0]
fmt.Printf("✅ Using device: %s\n", device.Name)

handle, err := pcap.OpenLive(device.Name, 65535, true, pcap.BlockForever)
if err != nil {
log.Fatal("Error opening device:", err)
}
defer handle.Close()

fmt.Println("📡 Capturing packets... (Ctrl+C to stop)\n")

packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
packets := packetSource.Packets()

packetCount := 0
startTime := time.Now()

for packet := range packets {
packetCount++

// Get IP layer
ipLayer := packet.Layer(layers.LayerTypeIPv4)
if ipLayer == nil {
continue
}

ip, _ := ipLayer.(*layers.IPv4)

// Get TCP layer
tcpLayer := packet.Layer(layers.LayerTypeTCP)
if tcpLayer != nil {
tcp, _ := tcpLayer.(*layers.TCP)
fmt.Printf("[%d] TCP: %s:%d → %s:%d\n",
packetCount,
ip.SrcIP, tcp.SrcPort,
ip.DstIP, tcp.DstPort,
)
}

// Get UDP layer
udpLayer := packet.Layer(layers.LayerTypeUDP)
if udpLayer != nil {
udp, _ := udpLayer.(*layers.UDP)
fmt.Printf("[%d] UDP: %s:%d → %s:%d\n",
packetCount,
ip.SrcIP, udp.SrcPort,
ip.DstIP, udp.DstPort,
)
}

// Print stats every 50 packets
if packetCount%50 == 0 {
elapsed := time.Since(startTime).Seconds()
pps := float64(packetCount) / elapsed
fmt.Printf("\n📊 Captured %d packets (%.0f pps)\n\n", packetCount, pps)
}
}
}
