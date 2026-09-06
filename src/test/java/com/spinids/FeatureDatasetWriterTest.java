package com.spinids;

import com.spinids.dataset.FeatureDatasetWriter;
import com.spinids.features.FlowFeatures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FeatureDatasetWriterTest {

    @TempDir
    Path tempDir;

    @Test
    public void testCsvDatasetFileCreationAndHeader() throws Exception {
        Path csvPath = tempDir.resolve("sub_dir").resolve("test_features.csv");
        String outputPath = csvPath.toString();

        List<FlowFeatures> featuresList = new ArrayList<>();
        featuresList.add(new FlowFeatures(
                "192.168.1.10", "192.168.1.20", 5000, 80, "TCP",
                1500L, 10L, 5000L, 500.0, 6.6667, 3333.3333,
                10L, 5L
        ));

        File file = FeatureDatasetWriter.writeDataset(featuresList, outputPath, "NORMAL");

        // 1. Verify file is created
        assertTrue(file.exists(), "CSV dataset file should be created");
        assertTrue(file.length() > 0, "CSV dataset file should not be empty");

        // 2. Read and verify content
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String header = reader.readLine();
            assertNotNull(header, "Header line must not be null");
            assertEquals(
                    "source_ip,destination_ip,source_port,destination_port,protocol," +
                    "flow_duration_ms,packet_count,total_bytes,avg_packet_size," +
                    "packets_per_second,bytes_per_second,forward_packet_count,reverse_packet_count,label",
                    header,
                    "CSV header must match required schema"
            );

            // 3. Verify data row
            String row = reader.readLine();
            assertNotNull(row, "Data row must be present");
            assertTrue(row.startsWith("192.168.1.10,192.168.1.20,5000,80,TCP,1500,10,5000,"),
                    "Data row should start with 5-tuple and metrics");

            // 4. Verify NORMAL label is present
            assertTrue(row.endsWith(",NORMAL"), "Row should end with NORMAL label");

            // No extra rows
            assertNull(reader.readLine(), "Should only contain header and 1 data row");
        }
    }

    @Test
    public void testFormatRowPrecisionAndEscaping() {
        FlowFeatures f = new FlowFeatures(
                "10.0.0.1", "10.0.0.2", 1234, 443, "TCP",
                1000L, 2L, 300L, 150.0, 2.0, 300.0,
                2L, 0L
        );

        String row = FeatureDatasetWriter.formatRow(f, "NORMAL");
        assertEquals("10.0.0.1,10.0.0.2,1234,443,TCP,1000,2,300,150.0000,2.0000,300.0000,2,0,NORMAL", row);
    }
}
