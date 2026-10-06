package com.spinids.dataset;

import com.spinids.dataset.DatasetManifestWriter.ManifestEntry;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Deterministic dataset splitting utility for SPIN-IDS.
 *
 * <p>Splits network packet window datasets into training (70%), validation (15%),
 * and test (15%) subsets strictly at the conversation / flow level (by flow_id).
 * All windows belonging to the same flow are kept exclusively within one split to
 * prevent flow-level data leakage between training and evaluation.</p>
 *
 * <p>Copies image files to split directories and writes corresponding split manifests.</p>
 */
public class DatasetSplitter {

    public static final String DEFAULT_NORMAL_MANIFEST = "dataset/images/normal_manifest.csv";
    public static final String DEFAULT_MALICIOUS_MANIFEST = "dataset/images/malicious_manifest.csv";
    public static final String DEFAULT_BASE_DIR = "dataset/images";

    public static final double DEFAULT_TRAIN_RATIO = 0.70;
    public static final double DEFAULT_VAL_RATIO = 0.15;
    public static final double DEFAULT_TEST_RATIO = 0.15;
    public static final long DEFAULT_RANDOM_SEED = 42L;

    /**
     * Data structure holding the results and metrics of a dataset split operation.
     */
    public static class SplitResult {
        private final List<ManifestEntry> trainEntries;
        private final List<ManifestEntry> valEntries;
        private final List<ManifestEntry> testEntries;

        private final Set<String> trainFlows;
        private final Set<String> valFlows;
        private final Set<String> testFlows;

        private final int copiedImagesCount;

        public SplitResult(List<ManifestEntry> trainEntries, List<ManifestEntry> valEntries, List<ManifestEntry> testEntries,
                           Set<String> trainFlows, Set<String> valFlows, Set<String> testFlows,
                           int copiedImagesCount) {
            this.trainEntries = trainEntries;
            this.valEntries = valEntries;
            this.testEntries = testEntries;
            this.trainFlows = trainFlows;
            this.valFlows = valFlows;
            this.testFlows = testFlows;
            this.copiedImagesCount = copiedImagesCount;
        }

        public List<ManifestEntry> getTrainEntries() {
            return trainEntries;
        }

        public List<ManifestEntry> getValEntries() {
            return valEntries;
        }

        public List<ManifestEntry> getTestEntries() {
            return testEntries;
        }

        public Set<String> getTrainFlows() {
            return trainFlows;
        }

        public Set<String> getValFlows() {
            return valFlows;
        }

        public Set<String> getTestFlows() {
            return testFlows;
        }

        public int getCopiedImagesCount() {
            return copiedImagesCount;
        }

        public long getTrainNormalCount() {
            return countByLabel(trainEntries, "NORMAL");
        }

        public long getTrainMaliciousCount() {
            return countByLabel(trainEntries, "MALICIOUS");
        }

        public long getValNormalCount() {
            return countByLabel(valEntries, "NORMAL");
        }

        public long getValMaliciousCount() {
            return countByLabel(valEntries, "MALICIOUS");
        }

        public long getTestNormalCount() {
            return countByLabel(testEntries, "NORMAL");
        }

        public long getTestMaliciousCount() {
            return countByLabel(testEntries, "MALICIOUS");
        }

        private static long countByLabel(List<ManifestEntry> entries, String label) {
            if (entries == null) return 0;
            return entries.stream()
                    .filter(e -> label.equalsIgnoreCase(e.getLabel()))
                    .count();
        }
    }

    public static void main(String[] args) {
        String normalManifestPath = DEFAULT_NORMAL_MANIFEST;
        String maliciousManifestPath = DEFAULT_MALICIOUS_MANIFEST;
        String baseDir = DEFAULT_BASE_DIR;
        long seed = DEFAULT_RANDOM_SEED;

        for (int i = 0; i < args.length; i++) {
            if ("--normal-manifest".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                normalManifestPath = args[++i];
            } else if ("--malicious-manifest".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                maliciousManifestPath = args[++i];
            } else if ("--base-dir".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                baseDir = args[++i];
            } else if ("--seed".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                try {
                    seed = Long.parseLong(args[++i]);
                } catch (NumberFormatException ignored) {}
            }
        }

        System.out.println("==================================================");
        System.out.println("SPIN-IDS DATASET SPLITTER");
        System.out.println("==================================================");
        System.out.println("Normal Manifest   : " + normalManifestPath);
        System.out.println("Malicious Manifest: " + maliciousManifestPath);
        System.out.println("Base Directory    : " + baseDir);
        System.out.println("Random Seed       : " + seed);
        System.out.println();

        try {
            File normalFile = new File(normalManifestPath);
            File maliciousFile = new File(maliciousManifestPath);

            if (!normalFile.exists()) {
                System.err.println("Error: Normal manifest not found: " + normalManifestPath);
                System.exit(1);
            }
            if (!maliciousFile.exists()) {
                System.err.println("Error: Malicious manifest not found: " + maliciousManifestPath);
                System.exit(1);
            }

            SplitResult result = splitDataset(normalFile, maliciousFile, new File(baseDir), seed);

            int totalFlows = result.getTrainFlows().size() + result.getValFlows().size() + result.getTestFlows().size();
            int totalWindows = result.getTrainEntries().size() + result.getValEntries().size() + result.getTestEntries().size();

            // Verify no flow overlap
            Set<String> trainValIntersect = new HashSet<>(result.getTrainFlows());
            trainValIntersect.retainAll(result.getValFlows());

            Set<String> trainTestIntersect = new HashSet<>(result.getTrainFlows());
            trainTestIntersect.retainAll(result.getTestFlows());

            Set<String> valTestIntersect = new HashSet<>(result.getValFlows());
            valTestIntersect.retainAll(result.getTestFlows());

            boolean isDisjoint = trainValIntersect.isEmpty() && trainTestIntersect.isEmpty() && valTestIntersect.isEmpty();

            System.out.println("--------------------------------------------------");
            System.out.println("SPLIT SUMMARY");
            System.out.println("--------------------------------------------------");
            System.out.printf("Total Unique Flows   : %d%n", totalFlows);
            System.out.printf("Total Windows/Images : %d%n", totalWindows);
            System.out.printf("Images Copied        : %d%n", result.getCopiedImagesCount());
            System.out.printf("Flow Exclusivity     : %s%n", isDisjoint ? "PASSED (Zero Flow Overlap)" : "FAILED");
            System.out.println();

            System.out.printf("TRAIN SPLIT (%.1f%% flows):%n", (totalFlows > 0 ? (result.getTrainFlows().size() * 100.0 / totalFlows) : 0));
            System.out.printf("  Flows     : %d%n", result.getTrainFlows().size());
            System.out.printf("  NORMAL    : %d images%n", result.getTrainNormalCount());
            System.out.printf("  MALICIOUS : %d images%n", result.getTrainMaliciousCount());
            System.out.printf("  Total     : %d images%n", result.getTrainEntries().size());
            System.out.println();

            System.out.printf("VAL SPLIT (%.1f%% flows):%n", (totalFlows > 0 ? (result.getValFlows().size() * 100.0 / totalFlows) : 0));
            System.out.printf("  Flows     : %d%n", result.getValFlows().size());
            System.out.printf("  NORMAL    : %d images%n", result.getValNormalCount());
            System.out.printf("  MALICIOUS : %d images%n", result.getValMaliciousCount());
            System.out.printf("  Total     : %d images%n", result.getValEntries().size());
            System.out.println();

            System.out.printf("TEST SPLIT (%.1f%% flows):%n", (totalFlows > 0 ? (result.getTestFlows().size() * 100.0 / totalFlows) : 0));
            System.out.printf("  Flows     : %d%n", result.getTestFlows().size());
            System.out.printf("  NORMAL    : %d images%n", result.getTestNormalCount());
            System.out.printf("  MALICIOUS : %d images%n", result.getTestMaliciousCount());
            System.out.printf("  Total     : %d images%n", result.getTestEntries().size());
            System.out.println();
            System.out.println("Manifests created:");
            System.out.println("  - " + new File(baseDir, "train_manifest.csv").getPath());
            System.out.println("  - " + new File(baseDir, "val_manifest.csv").getPath());
            System.out.println("  - " + new File(baseDir, "test_manifest.csv").getPath());
            System.out.println("==================================================");

        } catch (Exception e) {
            System.err.println("Fatal error during dataset splitting: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Executes deterministic flow-based dataset splitting using default ratios (70/15/15).
     */
    public static SplitResult splitDataset(File normalManifestFile, File maliciousManifestFile,
                                           File baseDir, long seed) throws IOException {
        return splitDataset(normalManifestFile, maliciousManifestFile, baseDir,
                DEFAULT_TRAIN_RATIO, DEFAULT_VAL_RATIO, DEFAULT_TEST_RATIO, seed);
    }

    /**
     * Executes deterministic flow-based dataset splitting with custom ratios.
     */
    public static SplitResult splitDataset(File normalManifestFile, File maliciousManifestFile,
                                           File baseDir, double trainRatio, double valRatio,
                                           double testRatio, long seed) throws IOException {

        List<ManifestEntry> normalEntries = DatasetManifestWriter.readManifest(normalManifestFile);
        List<ManifestEntry> maliciousEntries = DatasetManifestWriter.readManifest(maliciousManifestFile);

        // Group entries by flow_id
        Map<String, List<ManifestEntry>> flowToEntries = new LinkedHashMap<>();
        for (ManifestEntry entry : normalEntries) {
            flowToEntries.computeIfAbsent(entry.getFlowId(), k -> new ArrayList<>()).add(entry);
        }
        for (ManifestEntry entry : maliciousEntries) {
            flowToEntries.computeIfAbsent(entry.getFlowId(), k -> new ArrayList<>()).add(entry);
        }

        // Categorize flow_ids by label composition to ensure stratification
        List<String> normalOnlyFlows = new ArrayList<>();
        List<String> maliciousOnlyFlows = new ArrayList<>();
        List<String> bothFlows = new ArrayList<>();

        for (Map.Entry<String, List<ManifestEntry>> e : flowToEntries.entrySet()) {
            boolean hasNormal = false;
            boolean hasMalicious = false;
            for (ManifestEntry entry : e.getValue()) {
                if ("NORMAL".equalsIgnoreCase(entry.getLabel())) {
                    hasNormal = true;
                } else if ("MALICIOUS".equalsIgnoreCase(entry.getLabel())) {
                    hasMalicious = true;
                }
            }
            if (hasNormal && hasMalicious) {
                bothFlows.add(e.getKey());
            } else if (hasNormal) {
                normalOnlyFlows.add(e.getKey());
            } else {
                maliciousOnlyFlows.add(e.getKey());
            }
        }

        // Sort for initial determinism before shuffling
        Collections.sort(normalOnlyFlows);
        Collections.sort(maliciousOnlyFlows);
        Collections.sort(bothFlows);

        Random random = new Random(seed);

        Set<String> trainFlows = new HashSet<>();
        Set<String> valFlows = new HashSet<>();
        Set<String> testFlows = new HashSet<>();

        partitionFlows(bothFlows, trainRatio, valRatio, testRatio, random, trainFlows, valFlows, testFlows);
        partitionFlows(normalOnlyFlows, trainRatio, valRatio, testRatio, random, trainFlows, valFlows, testFlows);
        partitionFlows(maliciousOnlyFlows, trainRatio, valRatio, testRatio, random, trainFlows, valFlows, testFlows);

        // Prepare destination directories
        File trainNormalDir = new File(baseDir, "train/normal");
        File trainMaliciousDir = new File(baseDir, "train/malicious");
        File valNormalDir = new File(baseDir, "val/normal");
        File valMaliciousDir = new File(baseDir, "val/malicious");
        File testNormalDir = new File(baseDir, "test/normal");
        File testMaliciousDir = new File(baseDir, "test/malicious");

        trainNormalDir.mkdirs();
        trainMaliciousDir.mkdirs();
        valNormalDir.mkdirs();
        valMaliciousDir.mkdirs();
        testNormalDir.mkdirs();
        testMaliciousDir.mkdirs();

        int copiedImages = 0;

        List<ManifestEntry> trainEntries = new ArrayList<>();
        List<ManifestEntry> valEntries = new ArrayList<>();
        List<ManifestEntry> testEntries = new ArrayList<>();

        // Copy and populate each split
        for (String flowId : trainFlows) {
            List<ManifestEntry> entries = flowToEntries.get(flowId);
            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    File targetDir = "MALICIOUS".equalsIgnoreCase(entry.getLabel()) ? trainMaliciousDir : trainNormalDir;
                    ManifestEntry copiedEntry = copyImageAndCreateEntry(entry, targetDir, baseDir);
                    trainEntries.add(copiedEntry);
                    copiedImages++;
                }
            }
        }

        for (String flowId : valFlows) {
            List<ManifestEntry> entries = flowToEntries.get(flowId);
            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    File targetDir = "MALICIOUS".equalsIgnoreCase(entry.getLabel()) ? valMaliciousDir : valNormalDir;
                    ManifestEntry copiedEntry = copyImageAndCreateEntry(entry, targetDir, baseDir);
                    valEntries.add(copiedEntry);
                    copiedImages++;
                }
            }
        }

        for (String flowId : testFlows) {
            List<ManifestEntry> entries = flowToEntries.get(flowId);
            if (entries != null) {
                for (ManifestEntry entry : entries) {
                    File targetDir = "MALICIOUS".equalsIgnoreCase(entry.getLabel()) ? testMaliciousDir : testNormalDir;
                    ManifestEntry copiedEntry = copyImageAndCreateEntry(entry, targetDir, baseDir);
                    testEntries.add(copiedEntry);
                    copiedImages++;
                }
            }
        }

        // Write split manifests
        File trainManifest = new File(baseDir, "train_manifest.csv");
        File valManifest = new File(baseDir, "val_manifest.csv");
        File testManifest = new File(baseDir, "test_manifest.csv");

        DatasetManifestWriter.writeManifest(trainEntries, trainManifest.getPath());
        DatasetManifestWriter.writeManifest(valEntries, valManifest.getPath());
        DatasetManifestWriter.writeManifest(testEntries, testManifest.getPath());

        return new SplitResult(trainEntries, valEntries, testEntries,
                trainFlows, valFlows, testFlows, copiedImages);
    }

    private static void partitionFlows(List<String> flows, double trainRatio, double valRatio, double testRatio,
                                       Random random, Set<String> trainSet, Set<String> valSet, Set<String> testSet) {
        if (flows == null || flows.isEmpty()) {
            return;
        }

        List<String> shuffled = new ArrayList<>(flows);
        Collections.shuffle(shuffled, random);

        int total = shuffled.size();
        int trainCount;
        int valCount;
        int testCount;

        if (total == 1) {
            trainCount = 1;
            valCount = 0;
            testCount = 0;
        } else if (total == 2) {
            trainCount = 1;
            valCount = 1;
            testCount = 0;
        } else {
            trainCount = (int) Math.round(total * trainRatio);
            valCount = (int) Math.round(total * valRatio);

            // Ensure validation has at least 1 item for groups >= 3
            if (valCount == 0) {
                valCount = 1;
            }
            testCount = total - trainCount - valCount;
            // Ensure test has at least 1 item for groups >= 3
            if (testCount <= 0) {
                testCount = 1;
                trainCount = total - valCount - testCount;
            }
        }

        int index = 0;
        for (int i = 0; i < trainCount && index < total; i++) {
            trainSet.add(shuffled.get(index++));
        }
        for (int i = 0; i < valCount && index < total; i++) {
            valSet.add(shuffled.get(index++));
        }
        while (index < total) {
            testSet.add(shuffled.get(index++));
        }
    }

    private static ManifestEntry copyImageAndCreateEntry(ManifestEntry sourceEntry, File targetDir, File baseDir) throws IOException {
        String origPath = sourceEntry.getImagePath();
        File sourceFile = new File(origPath);

        // Fallback search if original relative path isn't directly resolved
        if (!sourceFile.exists()) {
            File alt = new File(baseDir, sourceFile.getName());
            if (alt.exists()) {
                sourceFile = alt;
            } else {
                File subAlt = new File(new File(baseDir, sourceEntry.getLabel().toLowerCase()), sourceFile.getName());
                if (subAlt.exists()) {
                    sourceFile = subAlt;
                }
            }
        }

        String fileName = new File(origPath).getName();
        File destFile = new File(targetDir, fileName);

        if (sourceFile.exists()) {
            Files.copy(sourceFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        String relativePath = normalizePath(destFile.getPath());
        return new ManifestEntry(
                relativePath,
                sourceEntry.getFlowId(),
                sourceEntry.getWindowIndex(),
                sourceEntry.getLabel(),
                sourceEntry.getSource(),
                sourceEntry.getTimestamp(),
                sourceEntry.getPacketCount()
        );
    }

    private static String normalizePath(String path) {
        if (path == null) return "";
        return path.replace('\\', '/');
    }
}
