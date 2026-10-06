package com.spinids;

import com.spinids.dataset.DatasetManifestWriter;
import com.spinids.dataset.DatasetManifestWriter.ManifestEntry;
import com.spinids.dataset.DatasetSplitter;
import com.spinids.dataset.DatasetSplitter.SplitResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class DatasetSplitterTest {

    @TempDir
    Path tempDir;

    private File normalManifestFile;
    private File maliciousManifestFile;
    private File baseDir;
    private List<File> createdSourceImages;

    @BeforeEach
    public void setup() throws Exception {
        baseDir = tempDir.resolve("images").toFile();
        baseDir.mkdirs();

        File normalImgDir = new File(baseDir, "normal");
        File malImgDir = new File(baseDir, "malicious");
        normalImgDir.mkdirs();
        malImgDir.mkdirs();

        createdSourceImages = new ArrayList<>();

        // Create 20 unique flows with multiple windows
        // Flows 1..10: Normal traffic
        // Flows 11..20: Malicious traffic
        // Flows 5 and 15: have overlapping endpoints to test shared flow ID handling
        List<ManifestEntry> normalEntries = new ArrayList<>();
        for (int f = 1; f <= 15; f++) {
            String flowId = String.format("192.168.1.%d:1234 <-> 10.0.0.1:80 [TCP]", f);
            int windowCount = (f % 3) + 1; // 1 to 3 windows per flow
            for (int w = 1; w <= windowCount; w++) {
                File imgFile = new File(normalImgDir, String.format("flow_%03d_window_%03d.png", f, w));
                createDummyPng(imgFile);
                createdSourceImages.add(imgFile);

                normalEntries.add(new ManifestEntry(
                        imgFile.getPath(), flowId, w, "NORMAL", "normal.pcapng", 1600000000000L + f * 1000 + w, 9
                ));
            }
        }

        List<ManifestEntry> maliciousEntries = new ArrayList<>();
        for (int f = 10; f <= 25; f++) {
            String flowId = String.format("192.168.1.%d:1234 <-> 10.0.0.1:80 [TCP]", f);
            int windowCount = (f % 2) + 1; // 1 to 2 windows per flow
            for (int w = 1; w <= windowCount; w++) {
                File imgFile = new File(malImgDir, String.format("flow_%03d_window_%03d.png", f, w));
                createDummyPng(imgFile);
                createdSourceImages.add(imgFile);

                maliciousEntries.add(new ManifestEntry(
                        imgFile.getPath(), flowId, w, "MALICIOUS", "malicious.pcap", 1600000500000L + f * 1000 + w, 9
                ));
            }
        }

        normalManifestFile = new File(baseDir, "normal_manifest.csv");
        maliciousManifestFile = new File(baseDir, "malicious_manifest.csv");

        DatasetManifestWriter.writeManifest(normalEntries, normalManifestFile.getPath());
        DatasetManifestWriter.writeManifest(maliciousEntries, maliciousManifestFile.getPath());
    }

    private void createDummyPng(File file) throws Exception {
        BufferedImage image = new BufferedImage(27, 27, BufferedImage.TYPE_INT_RGB);
        ImageIO.write(image, "PNG", file);
    }

    @Test
    public void testNoFlowIdAppearsInMoreThanOneSplit() throws Exception {
        SplitResult result = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 42L
        );

        Set<String> trainFlows = result.getTrainFlows();
        Set<String> valFlows = result.getValFlows();
        Set<String> testFlows = result.getTestFlows();

        assertFalse(trainFlows.isEmpty(), "Train flows must not be empty");
        assertFalse(valFlows.isEmpty(), "Validation flows must not be empty");
        assertFalse(testFlows.isEmpty(), "Test flows must not be empty");

        // Assert strictly pairwise disjoint
        Set<String> trainVal = new HashSet<>(trainFlows);
        trainVal.retainAll(valFlows);
        assertTrue(trainVal.isEmpty(), "No flow_id may appear in both train and validation: " + trainVal);

        Set<String> trainTest = new HashSet<>(trainFlows);
        trainTest.retainAll(testFlows);
        assertTrue(trainTest.isEmpty(), "No flow_id may appear in both train and test: " + trainTest);

        Set<String> valTest = new HashSet<>(valFlows);
        valTest.retainAll(testFlows);
        assertTrue(valTest.isEmpty(), "No flow_id may appear in both validation and test: " + valTest);

        // Verify window-level manifest entries also conform
        for (ManifestEntry entry : result.getTrainEntries()) {
            assertFalse(valFlows.contains(entry.getFlowId()), "Train manifest entry flow must not exist in val flows");
            assertFalse(testFlows.contains(entry.getFlowId()), "Train manifest entry flow must not exist in test flows");
        }
        for (ManifestEntry entry : result.getValEntries()) {
            assertFalse(trainFlows.contains(entry.getFlowId()), "Val manifest entry flow must not exist in train flows");
            assertFalse(testFlows.contains(entry.getFlowId()), "Val manifest entry flow must not exist in test flows");
        }
        for (ManifestEntry entry : result.getTestEntries()) {
            assertFalse(trainFlows.contains(entry.getFlowId()), "Test manifest entry flow must not exist in train flows");
            assertFalse(valFlows.contains(entry.getFlowId()), "Test manifest entry flow must not exist in val flows");
        }
    }

    @Test
    public void testBothLabelsRepresentedInEachSplit() throws Exception {
        SplitResult result = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 42L
        );

        assertTrue(result.getTrainNormalCount() > 0, "Train split should contain NORMAL images");
        assertTrue(result.getTrainMaliciousCount() > 0, "Train split should contain MALICIOUS images");

        assertTrue(result.getValNormalCount() > 0, "Validation split should contain NORMAL images");
        assertTrue(result.getValMaliciousCount() > 0, "Validation split should contain MALICIOUS images");

        assertTrue(result.getTestNormalCount() > 0, "Test split should contain NORMAL images");
        assertTrue(result.getTestMaliciousCount() > 0, "Test split should contain MALICIOUS images");
    }

    @Test
    public void testApproximately701515SplitRatios() throws Exception {
        SplitResult result = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 42L
        );

        int totalFlows = result.getTrainFlows().size() + result.getValFlows().size() + result.getTestFlows().size();
        assertEquals(25, totalFlows, "Total unique flows across flows 1..25 must equal 25");

        double trainPct = (double) result.getTrainFlows().size() / totalFlows;
        double valPct = (double) result.getValFlows().size() / totalFlows;
        double testPct = (double) result.getTestFlows().size() / totalFlows;

        // Tolerances for discrete rounding on 25 flows
        assertTrue(trainPct >= 0.60 && trainPct <= 0.80, "Train flow ratio should approximate ~70%, got " + trainPct);
        assertTrue(valPct >= 0.10 && valPct <= 0.25, "Val flow ratio should approximate ~15%, got " + valPct);
        assertTrue(testPct >= 0.10 && testPct <= 0.25, "Test flow ratio should approximate ~15%, got " + testPct);
    }

    @Test
    public void testAllSourceImagesRemainIntact() throws Exception {
        // Record source image lengths before split
        List<Long> lengthsBefore = new ArrayList<>();
        for (File img : createdSourceImages) {
            assertTrue(img.exists());
            lengthsBefore.add(img.length());
        }

        DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 42L
        );

        // Verify all source images are intact after split
        for (int i = 0; i < createdSourceImages.size(); i++) {
            File img = createdSourceImages.get(i);
            assertTrue(img.exists(), "Source image must remain intact: " + img.getPath());
            assertEquals(lengthsBefore.get(i), img.length(), "Source image byte length must not change");
        }
    }

    @Test
    public void testCopiedImagesExistInSplitDirectoriesAndManifestsCreated() throws Exception {
        SplitResult result = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 42L
        );

        assertTrue(result.getCopiedImagesCount() > 0, "Images must be copied");

        // Check manifest files
        File trainManifest = new File(baseDir, "train_manifest.csv");
        File valManifest = new File(baseDir, "val_manifest.csv");
        File testManifest = new File(baseDir, "test_manifest.csv");

        assertTrue(trainManifest.exists());
        assertTrue(valManifest.exists());
        assertTrue(testManifest.exists());

        // Verify each entry in train manifest points to an existing file in train directory
        List<ManifestEntry> trainEntries = DatasetManifestWriter.readManifest(trainManifest);
        assertEquals(result.getTrainEntries().size(), trainEntries.size());
        for (ManifestEntry entry : trainEntries) {
            File file = new File(entry.getImagePath());
            assertTrue(file.exists(), "Copied train image must exist on disk: " + file.getPath());
            assertTrue(entry.getImagePath().contains("/train/"), "Train image path must be inside train split directory");
        }

        // Verify val entries
        List<ManifestEntry> valEntries = DatasetManifestWriter.readManifest(valManifest);
        assertEquals(result.getValEntries().size(), valEntries.size());
        for (ManifestEntry entry : valEntries) {
            File file = new File(entry.getImagePath());
            assertTrue(file.exists(), "Copied val image must exist on disk: " + file.getPath());
            assertTrue(entry.getImagePath().contains("/val/"), "Val image path must be inside val split directory");
        }

        // Verify test entries
        List<ManifestEntry> testEntries = DatasetManifestWriter.readManifest(testManifest);
        assertEquals(result.getTestEntries().size(), testEntries.size());
        for (ManifestEntry entry : testEntries) {
            File file = new File(entry.getImagePath());
            assertTrue(file.exists(), "Copied test image must exist on disk: " + file.getPath());
            assertTrue(entry.getImagePath().contains("/test/"), "Test image path must be inside test split directory");
        }
    }

    @Test
    public void testDeterministicSplittingWithFixedSeed() throws Exception {
        SplitResult run1 = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 12345L
        );
        SplitResult run2 = DatasetSplitter.splitDataset(
                normalManifestFile, maliciousManifestFile, baseDir, 12345L
        );

        assertEquals(run1.getTrainFlows(), run2.getTrainFlows(), "Identical seeds must produce identical train flows");
        assertEquals(run1.getValFlows(), run2.getValFlows(), "Identical seeds must produce identical val flows");
        assertEquals(run1.getTestFlows(), run2.getTestFlows(), "Identical seeds must produce identical test flows");
    }
}
