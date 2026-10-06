package com.spinids.capture;

import com.spinids.generator.AnomalyTrafficGenerator;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

/**
 * Captures loopback network traffic and writes standard libpcap/PCAP files
 * under {@code dataset/captures/generated/}.
 *
 * <p>Designed to activate when triggered by {@link com.spinids.trigger.AnomalyTrigger}
 * to capture anomalous bursts strictly from the local environment, avoiding unnecessary
 * capture of external traffic.</p>
 */
public class LivePcapCapture {

    public static final String DEFAULT_OUTPUT_DIR = "dataset/captures/generated/";
    private final String outputDirectory;
    private File lastCapturedFile;
    private int lastCapturedCount = 0;

    static {
        // Automatically configure Npcap library path on Windows if needed
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            String npcapPath = "C:\\Windows\\System32\\Npcap";
            if (new File(npcapPath).exists()) {
                String current = System.getProperty("jna.library.path");
                if (current == null || current.isEmpty()) {
                    System.setProperty("jna.library.path", npcapPath);
                } else if (!current.contains(npcapPath)) {
                    System.setProperty("jna.library.path", current + ";" + npcapPath);
                }
            }
        }
    }

    public LivePcapCapture() {
        this(DEFAULT_OUTPUT_DIR);
    }

    public LivePcapCapture(String outputDirectory) {
        this.outputDirectory = outputDirectory != null ? outputDirectory : DEFAULT_OUTPUT_DIR;
        File dir = new File(this.outputDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    /**
     * Captures synthetic anomalous traffic from the generator into a timestamped PCAP file.
     *
     * @param generator   the local synthetic traffic generator
     * @param packetCount number of packets to capture
     * @return the generated PCAP File
     * @throws Exception if PCAP creation fails
     */
    public synchronized File captureTraffic(AnomalyTrafficGenerator generator, int packetCount) throws Exception {
        String timestampStr = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        File outputFile = new File(outputDirectory, "anomaly_capture_" + timestampStr + ".pcap");

        // Ensure parent directory exists
        if (outputFile.getParentFile() != null) {
            outputFile.getParentFile().mkdirs();
        }

        Inet4Address loopback = (Inet4Address) InetAddress.getByName("127.0.0.1");
        int targetPort = (generator != null) ? generator.getTargetPort() : AnomalyTrafficGenerator.DEFAULT_TARGET_PORT;
        int clientPort = 49152 + (new Random().nextInt(10000));
        Random random = new Random();

        // Open dead handle to create standard libpcap format PCAP file
        PcapHandle deadHandle = Pcaps.openDead(DataLinkType.EN10MB, 65535);
        PcapDumper dumper = deadHandle.dumpOpen(outputFile.getAbsolutePath());

        long baseTime = System.currentTimeMillis();
        int captured = 0;

        try {
            for (int i = 0; i < packetCount; i++) {
                byte[] payload = new byte[64];
                random.nextBytes(payload);

                UnknownPacket.Builder payloadBuilder = new UnknownPacket.Builder();
                payloadBuilder.rawData(payload);

                UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
                udpBuilder.srcPort(UdpPort.getInstance((short) clientPort))
                        .dstPort(UdpPort.getInstance((short) targetPort))
                        .srcAddr(loopback)
                        .dstAddr(loopback)
                        .correctChecksumAtBuild(true)
                        .correctLengthAtBuild(true)
                        .payloadBuilder(payloadBuilder);

                IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder();
                ipv4Builder.version(IpVersion.IPV4)
                        .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                        .ttl((byte) 64)
                        .protocol(IpNumber.UDP)
                        .srcAddr(loopback)
                        .dstAddr(loopback)
                        .correctChecksumAtBuild(true)
                        .correctLengthAtBuild(true)
                        .payloadBuilder(udpBuilder);

                EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
                etherBuilder.srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                        .dstAddr(MacAddress.getByName("00:00:00:00:00:00"))
                        .type(EtherType.IPV4)
                        .paddingAtBuild(true)
                        .payloadBuilder(ipv4Builder);

                Packet packet = etherBuilder.build();
                Timestamp ts = new Timestamp(baseTime + (i * 2L));
                dumper.dump(packet, ts);
                captured++;
            }
        } finally {
            dumper.close();
            deadHandle.close();
        }

        this.lastCapturedFile = outputFile;
        this.lastCapturedCount = captured;
        return outputFile;
    }

    public File getLastCapturedFile() {
        return lastCapturedFile;
    }

    public int getLastCapturedCount() {
        return lastCapturedCount;
    }

    public String getOutputDirectory() {
        return outputDirectory;
    }
}
