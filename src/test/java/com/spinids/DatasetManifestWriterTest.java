package com.spinids;

import com.spinids.dataset.DatasetManifestWriter;
import com.spinids.dataset.DatasetManifestWriter.ManifestEntry;
import com.spinids.image.SequentialPacketWindow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DatasetManifestWriterTest {

    @TempDir
    Path tempDir;

    @Test
    public void testManifestFileCreationAndHeader() throws Exception {
        Path manifestPath = tempDir.resolve("images").resolve("dataset_manifest.csv");
        String outputPath = manifestPath.toString();

        List<ManifestEntry> entries = new ArrayList<>();
        entries.add(new ManifestEntry(
                "dataset/images/flow_001_window_001.png",
                "192.168.1.10:5000 <-> 10.0.0.1:80 [TCP]",
                1,
                "NORMAL",
                "normal_traffic.pcapng",
                1600000000000L,
                9
        ));
        entries.add(new ManifestEntry(
                "dataset/images/flow_002_window_001.png",
                "192.168.1.50:4444 <-> 10.0.0.5:80 [TCP]",
                1,
                "MALICIOUS",
                "attack_traffic.pcap",
                1600000005000L,
                4
        ));

        File file = DatasetManifestWriter.writeManifest(entries, outputPath);

        assertTrue(file.exists());
        assertTrue(file.length() > 0);

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String header = reader.readLine();
            assertNotNull(header);
            assertEquals("image_path,flow_id,window_index,label,source,timestamp,packet_count", header);

            String row1 = reader.readLine();
            assertNotNull(row1);
            assertEquals("dataset/images/flow_001_window_001.png,192.168.1.10:5000 <-> 10.0.0.1:80 [TCP],1,NORMAL,normal_traffic.pcapng,1600000000000,9", row1);

            String row2 = reader.readLine();
            assertNotNull(row2);
            assertEquals("dataset/images/flow_002_window_001.png,192.168.1.50:4444 <-> 10.0.0.5:80 [TCP],1,MALICIOUS,attack_traffic.pcap,1600000005000,4", row2);

            assertNull(reader.readLine());
        }
    }

    @Test
    public void testCreateEntryFromSequentialPacketWindow() {
        SequentialPacketWindow window = new SequentialPacketWindow(
                "10.0.0.1:1234 <-> 10.0.0.2:80 [TCP]",
                5,
                2,
                "MALICIOUS"
        );
        window.addPacket(null, 1610000000000L, SequentialPacketWindow.PacketDirection.FORWARD, 1);
        window.addPacket(null, 1610000000100L, SequentialPacketWindow.PacketDirection.BACKWARD, 2);

        File dummyImage = new File("dataset\\images\\flow_005_window_002.png");
        ManifestEntry entry = DatasetManifestWriter.createEntry(dummyImage, window, "capture.pcap");

        assertNotNull(entry);
        assertEquals("dataset/images/flow_005_window_002.png", entry.getImagePath());
        assertEquals("10.0.0.1:1234 <-> 10.0.0.2:80 [TCP]", entry.getFlowId());
        assertEquals(2, entry.getWindowIndex());
        assertEquals("MALICIOUS", entry.getLabel());
        assertEquals("capture.pcap", entry.getSource());
        assertEquals(1610000000000L, entry.getTimestamp());
        assertEquals(2, entry.getPacketCount());
    }

    @Test
    public void testAppendManifestPreservesExistingEntriesWithoutDuplicateHeader() throws Exception {
        Path manifestPath = tempDir.resolve("dataset_manifest.csv");
        String outputPath = manifestPath.toString();

        List<ManifestEntry> batch1 = List.of(
                new ManifestEntry("img1.png", "flow1", 1, "NORMAL", "pcap1.pcap", 1000L, 9)
        );
        List<ManifestEntry> batch2 = List.of(
                new ManifestEntry("img2.png", "flow2", 1, "MALICIOUS", "pcap2.pcap", 2000L, 5)
        );

        DatasetManifestWriter.writeManifest(batch1, outputPath);
        DatasetManifestWriter.appendManifest(batch2, outputPath);

        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(manifestPath.toFile()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }

        // Header + 2 data rows
        assertEquals(3, lines.size());
        assertEquals(DatasetManifestWriter.CSV_HEADER, lines.get(0));
        assertTrue(lines.get(1).startsWith("img1.png,flow1"));
        assertTrue(lines.get(2).startsWith("img2.png,flow2"));
    }

    @Test
    public void testLabelAwareManifestPaths() {
        assertEquals("dataset/images/normal_manifest.csv", DatasetManifestWriter.NORMAL_MANIFEST_PATH);
        assertEquals("dataset/images/malicious_manifest.csv", DatasetManifestWriter.MALICIOUS_MANIFEST_PATH);

        assertEquals(DatasetManifestWriter.NORMAL_MANIFEST_PATH, DatasetManifestWriter.getDefaultManifestPath("NORMAL"));
        assertEquals(DatasetManifestWriter.NORMAL_MANIFEST_PATH, DatasetManifestWriter.getDefaultManifestPath("normal"));
        assertEquals(DatasetManifestWriter.MALICIOUS_MANIFEST_PATH, DatasetManifestWriter.getDefaultManifestPath("MALICIOUS"));
        assertEquals(DatasetManifestWriter.MALICIOUS_MANIFEST_PATH, DatasetManifestWriter.getDefaultManifestPath("malicious"));
        assertEquals(DatasetManifestWriter.NORMAL_MANIFEST_PATH, DatasetManifestWriter.getDefaultManifestPath(null));
    }

    @Test
    public void testReadManifestParsesEntriesCorrectly() throws Exception {
        Path manifestPath = tempDir.resolve("test_read_manifest.csv");

        List<ManifestEntry> original = List.of(
                new ManifestEntry("dataset/images/normal/img1.png", "flow1", 1, "NORMAL", "capture.pcap", 1000L, 9),
                new ManifestEntry("dataset/images/malicious/img2.png", "flow2", 2, "MALICIOUS", "mal.pcap", 2000L, 4)
        );

        DatasetManifestWriter.writeManifest(original, manifestPath.toString());
        List<ManifestEntry> loaded = DatasetManifestWriter.readManifest(manifestPath.toFile());

        assertEquals(2, loaded.size());
        assertEquals("dataset/images/normal/img1.png", loaded.get(0).getImagePath());
        assertEquals("flow1", loaded.get(0).getFlowId());
        assertEquals(1, loaded.get(0).getWindowIndex());
        assertEquals("NORMAL", loaded.get(0).getLabel());
        assertEquals("capture.pcap", loaded.get(0).getSource());
        assertEquals(1000L, loaded.get(0).getTimestamp());
        assertEquals(9, loaded.get(0).getPacketCount());

        assertEquals("dataset/images/malicious/img2.png", loaded.get(1).getImagePath());
        assertEquals("flow2", loaded.get(1).getFlowId());
        assertEquals(2, loaded.get(1).getWindowIndex());
        assertEquals("MALICIOUS", loaded.get(1).getLabel());
        assertEquals("mal.pcap", loaded.get(1).getSource());
        assertEquals(2000L, loaded.get(1).getTimestamp());
        assertEquals(4, loaded.get(1).getPacketCount());
    }

    @Test
    public void testNoCrossContaminationBetweenNormalAndMaliciousManifests() throws Exception {
        Path normalPath = tempDir.resolve("normal_manifest.csv");
        Path malPath = tempDir.resolve("malicious_manifest.csv");

        List<ManifestEntry> normalBatch = List.of(
                new ManifestEntry("dataset/images/normal/f1_w1.png", "flow_norm_1", 1, "NORMAL", "normal.pcapng", 1000L, 9),
                new ManifestEntry("dataset/images/normal/f1_w2.png", "flow_norm_1", 2, "NORMAL", "normal.pcapng", 1050L, 9)
        );

        List<ManifestEntry> malBatch = List.of(
                new ManifestEntry("dataset/images/malicious/f2_w1.png", "flow_mal_1", 1, "MALICIOUS", "malicious.pcap", 2000L, 9),
                new ManifestEntry("dataset/images/malicious/f2_w2.png", "flow_mal_1", 2, "MALICIOUS", "malicious.pcap", 2050L, 4)
        );

        DatasetManifestWriter.writeManifest(normalBatch, normalPath.toString());
        DatasetManifestWriter.writeManifest(malBatch, malPath.toString());

        List<ManifestEntry> readNormal = DatasetManifestWriter.readManifest(normalPath.toFile());
        List<ManifestEntry> readMal = DatasetManifestWriter.readManifest(malPath.toFile());

        assertEquals(2, readNormal.size());
        for (ManifestEntry e : readNormal) {
            assertEquals("NORMAL", e.getLabel(), "Normal manifest must contain only NORMAL labels");
            assertTrue(e.getImagePath().contains("/normal/"), "Normal manifest images must be in normal directory");
        }

        assertEquals(2, readMal.size());
        for (ManifestEntry e : readMal) {
            assertEquals("MALICIOUS", e.getLabel(), "Malicious manifest must contain only MALICIOUS labels");
            assertTrue(e.getImagePath().contains("/malicious/"), "Malicious manifest images must be in malicious directory");
        }
    }
}
