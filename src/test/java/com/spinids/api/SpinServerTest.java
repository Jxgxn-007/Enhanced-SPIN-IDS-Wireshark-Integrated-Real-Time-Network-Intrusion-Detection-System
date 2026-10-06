package com.spinids.api;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class SpinServerTest {

    private static SpinServer server;
    private static int serverPort;

    @BeforeAll
    public static void setup() throws Exception {
        // Find an open port
        try (ServerSocket s = new ServerSocket(0)) {
            serverPort = s.getLocalPort();
        }
        server = new SpinServer(serverPort);
        server.start();
    }

    @AfterAll
    public static void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    private String getUrl(String path) {
        return "http://localhost:" + serverPort + path;
    }

    private String readResponse(HttpURLConnection conn) throws Exception {
        int code = conn.getResponseCode();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream(),
                StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    @Test
    public void testStatusEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/status")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        assertEquals("*", conn.getHeaderField("Access-Control-Allow-Origin"));
        String json = readResponse(conn);
        assertTrue(json.contains("engineState"));
        assertTrue(json.contains("subsystems"));
        assertTrue(json.contains("stats"));
    }

    @Test
    public void testRateEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/telemetry/rate")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String json = readResponse(conn);
        assertTrue(json.contains("pps"));
        assertTrue(json.contains("threshold"));
    }

    @Test
    public void testEngineStartAndStop() throws Exception {
        // Test stop
        HttpURLConnection stopConn = (HttpURLConnection) new URL(getUrl("/api/engine/stop")).openConnection();
        stopConn.setRequestMethod("POST");
        assertEquals(200, stopConn.getResponseCode());
        String stopJson = readResponse(stopConn);
        assertTrue(stopJson.contains("STOPPED"));

        // Test start
        HttpURLConnection startConn = (HttpURLConnection) new URL(getUrl("/api/engine/start")).openConnection();
        startConn.setRequestMethod("POST");
        assertEquals(200, startConn.getResponseCode());
        String startJson = readResponse(startConn);
        assertTrue(startJson.contains("RUNNING"));
    }

    @Test
    public void testDetectionsEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/detections?limit=10")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String json = readResponse(conn);
        assertTrue(json.startsWith("["));
        assertTrue(json.contains("prediction"));
    }

    @Test
    public void testWindowsEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/windows")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String json = readResponse(conn);
        assertTrue(json.startsWith("["));
    }

    @Test
    public void testWindowDetailEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/windows/detail?index=2")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String json = readResponse(conn);
        assertTrue(json.contains("matrixPreview"));
        assertTrue(json.contains("packets"));
    }

    @Test
    public void testPcapsListEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/pcaps")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String json = readResponse(conn);
        assertTrue(json.startsWith("["));
    }

    @Test
    public void testCorsPreflightOptions() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/status")).openConnection();
        conn.setRequestMethod("OPTIONS");

        assertEquals(204, conn.getResponseCode());
        assertEquals("*", conn.getHeaderField("Access-Control-Allow-Origin"));
        assertTrue(conn.getHeaderField("Access-Control-Allow-Methods").contains("GET"));
    }

    @Test
    public void testStaticFrontendServing() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        String contentType = conn.getHeaderField("Content-Type");
        assertTrue(contentType != null && contentType.contains("text/html"));
        String html = readResponse(conn);
        assertTrue(html.contains("SPIN-IDS"));
    }

    @Test
    public void testInterfacesEndpoint() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(getUrl("/api/interfaces")).openConnection();
        conn.setRequestMethod("GET");

        assertEquals(200, conn.getResponseCode());
        assertEquals("*", conn.getHeaderField("Access-Control-Allow-Origin"));
        String json = readResponse(conn);
        assertTrue(json.startsWith("["));
    }

    @Test
    public void testEngineInterfaceEndpoint() throws Exception {
        // GET
        HttpURLConnection getConn = (HttpURLConnection) new URL(getUrl("/api/engine/interface")).openConnection();
        getConn.setRequestMethod("GET");
        assertEquals(200, getConn.getResponseCode());
        String getJson = readResponse(getConn);
        assertTrue(getJson.contains("selectedInterface") || getJson.contains("description"));

        // POST invalid interface
        HttpURLConnection postConn = (HttpURLConnection) new URL(getUrl("/api/engine/interface")).openConnection();
        postConn.setRequestMethod("POST");
        postConn.setDoOutput(true);
        postConn.setRequestProperty("Content-Type", "application/json");
        try (OutputStream os = postConn.getOutputStream()) {
            os.write("{\"interfaceName\":\"InvalidInterface9999\"}".getBytes(StandardCharsets.UTF_8));
        }
        assertEquals(404, postConn.getResponseCode());
    }
}
