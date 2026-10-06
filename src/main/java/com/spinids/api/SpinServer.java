package com.spinids.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spinids.api.dto.*;
import com.spinids.detection.DetectionResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Embedded HTTP REST and SSE Server for SPIN-IDS.
 * Provides live telemetry, engine control, network interface discovery/selection,
 * PCAP export, and hosts the React frontend UI.
 */
public class SpinServer {

    public static final int DEFAULT_PORT = 8080;
    private final int port;
    private final SpinEngineController controller;
    private final ObjectMapper mapper;
    private HttpServer server;
    private ExecutorService executor;
    private final ScheduledExecutorService telemetryScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SpinTelemetry-Scheduler");
        t.setDaemon(true);
        return t;
    });

    public SpinServer() {
        this(DEFAULT_PORT, SpinEngineController.getInstance());
    }

    public SpinServer(int port) {
        this(port, SpinEngineController.getInstance());
    }

    public SpinServer(int port, SpinEngineController controller) {
        this.port = port;
        this.controller = controller;
        this.mapper = new ObjectMapper();
    }

    public synchronized void start() throws IOException {
        if (server != null) return;

        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "SpinHttp-Worker");
            t.setDaemon(true);
            return t;
        });

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(executor);

        // Register endpoints
        server.createContext("/", new StaticFileHandler());
        server.createContext("/api/status", new StatusHandler());
        server.createContext("/api/telemetry/rate", new RateHandler());
        server.createContext("/api/stream", new SseStreamHandler());
        server.createContext("/api/interfaces", new InterfacesHandler());
        server.createContext("/api/engine/interface", new EngineInterfaceHandler());
        server.createContext("/api/engine/start", new EngineStartHandler());
        server.createContext("/api/engine/stop", new EngineStopHandler());
        server.createContext("/api/engine/simulate", new SimulateHandler());
        server.createContext("/api/detections", new DetectionsHandler());
        server.createContext("/api/pcaps", new PcapsHandler());
        server.createContext("/api/pcaps/download", new PcapDownloadHandler());
        server.createContext("/api/windows", new WindowsHandler());
        server.createContext("/api/windows/detail", new WindowDetailHandler());
        server.createContext("/api/logs", new LogsHandler());

        server.start();
        System.out.println("[*] SPIN-IDS Server active at: http://localhost:" + port + "/");
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(1);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        telemetryScheduler.shutdownNow();
    }

    public int getPort() {
        return (server != null) ? server.getAddress().getPort() : port;
    }

    private void applyCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization");
    }

    private boolean handlePreflight(HttpExchange exchange) throws IOException {
        applyCorsHeaders(exchange);
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return true;
        }
        return false;
    }

    private void sendJson(HttpExchange exchange, int statusCode, Object data) throws IOException {
        applyCorsHeaders(exchange);
        byte[] bytes = mapper.writeValueAsBytes(data);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) return params;
        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String val = pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
            params.put(key, val);
        }
        return params;
    }

    // --- HANDLERS ---

    private class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;

            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/api/")) {
                String msg = "Not Found: " + path;
                exchange.sendResponseHeaders(404, msg.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(msg.getBytes(StandardCharsets.UTF_8));
                }
                return;
            }

            // Resolve frontend directory: prefer frontend/dist, then spin-ids/frontend/dist, then frontend
            File distDir = new File("frontend/dist");
            if (!distDir.exists()) {
                distDir = new File("spin-ids/frontend/dist");
            }
            if (!distDir.exists()) {
                distDir = new File("frontend");
                if (!distDir.exists()) {
                    distDir = new File("spin-ids/frontend");
                }
            }

            File targetFile;
            if (path.equals("/") || path.equals("/index.html")) {
                targetFile = new File(distDir, "index.html");
            } else {
                targetFile = new File(distDir, path.startsWith("/") ? path.substring(1) : path);
                // SPA fallback if asset doesn't exist but it's a client-side route
                if (!targetFile.exists() && !path.startsWith("/assets/")) {
                    targetFile = new File(distDir, "index.html");
                }
            }

            if (targetFile.exists() && targetFile.isFile()) {
                applyCorsHeaders(exchange);
                String mime = "application/octet-stream";
                String name = targetFile.getName().toLowerCase();
                if (name.endsWith(".html")) mime = "text/html; charset=utf-8";
                else if (name.endsWith(".js")) mime = "application/javascript; charset=utf-8";
                else if (name.endsWith(".css")) mime = "text/css; charset=utf-8";
                else if (name.endsWith(".svg")) mime = "image/svg+xml";
                else if (name.endsWith(".png")) mime = "image/png";
                else if (name.endsWith(".ico")) mime = "image/x-icon";
                else if (name.endsWith(".json")) mime = "application/json";

                exchange.getResponseHeaders().set("Content-Type", mime);
                byte[] bytes = Files.readAllBytes(targetFile.toPath());
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
                return;
            }

            String msg = "Not Found: " + path;
            exchange.sendResponseHeaders(404, msg.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(msg.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            sendJson(exchange, 200, controller.getStatus());
        }
    }

    private class RateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            StatusResponse status = controller.getStatus();
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("timestamp", System.currentTimeMillis());
            resp.put("pps", status.getCurrentPps());
            resp.put("threshold", status.getThresholdPps());
            resp.put("anomalous", status.isAnomalous());
            resp.put("monitoringMode", status.getMonitoringMode());
            resp.put("selectedInterface", status.getSelectedInterface());
            resp.put("interfaceDescription", status.getInterfaceDescription());
            resp.put("captureInProgress", status.isCaptureInProgress());
            resp.put("cooldownActive", status.isCooldownActive());
            sendJson(exchange, 200, resp);
        }
    }

    private class InterfacesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            sendJson(exchange, 200, controller.getAvailableInterfaces());
        }
    }

    private class EngineInterfaceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("selectedInterface", controller.getSelectedInterfaceName());
                resp.put("description", controller.getActiveInterfaceDisplayName());
                resp.put("monitoringMode", controller.getStatus().getMonitoringMode());
                sendJson(exchange, 200, resp);
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                SelectInterfaceRequest req = null;
                try {
                    InputStream is = exchange.getRequestBody();
                    if (is != null) {
                        req = mapper.readValue(is, SelectInterfaceRequest.class);
                    }
                } catch (Exception ignored) {}

                if (req == null || req.getInterfaceName() == null || req.getInterfaceName().trim().isEmpty()) {
                    sendJson(exchange, 400, Map.of("error", "Missing required field: interfaceName"));
                    return;
                }

                boolean success = controller.selectInterface(req.getInterfaceName());
                if (success) {
                    Map<String, Object> resp = new LinkedHashMap<>();
                    resp.put("status", "OK");
                    resp.put("selectedInterface", controller.getSelectedInterfaceName());
                    resp.put("description", controller.getActiveInterfaceDisplayName());
                    resp.put("message", "Network interface updated to " + controller.getActiveInterfaceDisplayName());
                    sendJson(exchange, 200, resp);
                } else {
                    sendJson(exchange, 404, Map.of("error", "Network interface not found: " + req.getInterfaceName()));
                }
                return;
            }

            sendJson(exchange, 405, Map.of("error", "Method not allowed. Use GET or POST."));
        }
    }

    private class EngineStartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            controller.startMonitoring();
            sendJson(exchange, 200, Map.of(
                    "status", "RUNNING",
                    "interface", controller.getActiveInterfaceDisplayName(),
                    "message", "Live packet monitoring active on " + controller.getActiveInterfaceDisplayName()
            ));
        }
    }

    private class EngineStopHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            controller.stopMonitoring();
            sendJson(exchange, 200, Map.of("status", "STOPPED", "message", "Live packet monitoring halted"));
        }
    }

    private class SimulateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, Map.of("error", "Method not allowed. Use POST."));
                return;
            }

            SimulationRequest req = new SimulationRequest();
            try {
                InputStream is = exchange.getRequestBody();
                if (is != null && is.available() > 0) {
                    req = mapper.readValue(is, SimulationRequest.class);
                }
            } catch (Exception ignored) {}

            try {
                SimulationResponse resp = controller.triggerSimulation(req.getBurstRate(), req.getBurstPackets(), req.getTargetPort());
                sendJson(exchange, 200, resp);
            } catch (Exception e) {
                sendJson(exchange, 500, Map.of("error", "Simulation failed: " + e.getMessage()));
            }
        }
    }

    private class DetectionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            Map<String, String> q = parseQueryParams(exchange.getRequestURI().getQuery());
            String label = q.getOrDefault("label", "ALL");
            int limit = 50;
            if (q.containsKey("limit")) {
                try { limit = Integer.parseInt(q.get("limit")); } catch (Exception ignored) {}
            }
            sendJson(exchange, 200, controller.getRecentDetections(label, limit));
        }
    }

    private class PcapsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            sendJson(exchange, 200, controller.getPcapFiles());
        }
    }

    private class PcapDownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            Map<String, String> q = parseQueryParams(exchange.getRequestURI().getQuery());
            String filename = q.get("file");
            File f = controller.getPcapFile(filename);

            if (f == null || !f.exists()) {
                sendJson(exchange, 404, Map.of("error", "PCAP file not found: " + filename));
                return;
            }

            applyCorsHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "application/vnd.tcpdump.pcap");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + f.getName() + "\"");
            exchange.sendResponseHeaders(200, f.length());

            try (InputStream in = new FileInputStream(f);
                 OutputStream out = exchange.getResponseBody()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
        }
    }

    private class WindowsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            sendJson(exchange, 200, controller.getAllWindowDetails());
        }
    }

    private class WindowDetailHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            Map<String, String> q = parseQueryParams(exchange.getRequestURI().getQuery());
            int index = 1;
            if (q.containsKey("index")) {
                try { index = Integer.parseInt(q.get("index")); } catch (Exception ignored) {}
            }
            WindowDetailDto detail = controller.getWindowDetail(index);
            if (detail != null) {
                sendJson(exchange, 200, detail);
            } else {
                sendJson(exchange, 404, Map.of("error", "Window not found: " + index));
            }
        }
    }

    private class LogsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;
            Map<String, String> q = parseQueryParams(exchange.getRequestURI().getQuery());
            String format = q.getOrDefault("format", "json");

            if ("csv".equalsIgnoreCase(format)) {
                applyCorsHeaders(exchange);
                exchange.getResponseHeaders().set("Content-Type", "text/csv; charset=utf-8");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"detection_log.csv\"");
                byte[] bytes = controller.getDetectionLogsCsv().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                sendJson(exchange, 200, controller.getRecentDetections("ALL", 100));
            }
        }
    }

    private class SseStreamHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (handlePreflight(exchange)) return;

            applyCorsHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-transform");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("X-Accel-Buffering", "no");
            exchange.sendResponseHeaders(200, 0); // chunked transfer

            final OutputStream os = exchange.getResponseBody();
            final PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8), true);

            // Send initial connection event
            writer.print("event: connected\ndata: {\"status\":\"connected\",\"timestamp\":" + System.currentTimeMillis() + "}\n\n");
            writer.flush();

            // Listener for live detection broadcasts
            Consumer<DetectionResult> detectionConsumer = dr -> {
                synchronized (writer) {
                    try {
                        String json = mapper.writeValueAsString(SpinEngineController.toDto(dr));
                        writer.print("event: detection\ndata: " + json + "\n\n");
                        writer.flush();
                    } catch (Exception ignored) {}
                }
            };
            controller.addDetectionListener(detectionConsumer);

            // Listener for pipeline / anomaly / capture events
            Consumer<Map<String, Object>> sseEventConsumer = eventMap -> {
                synchronized (writer) {
                    try {
                        String eventType = (String) eventMap.getOrDefault("type", "message");
                        String json = mapper.writeValueAsString(eventMap);
                        writer.print("event: " + eventType + "\ndata: " + json + "\n\n");
                        writer.flush();
                    } catch (Exception ignored) {}
                }
            };
            controller.addSseEventListener(sseEventConsumer);

            // Periodic telemetry rate ticker (every 1000ms)
            ScheduledFuture<?> ticker = telemetryScheduler.scheduleAtFixedRate(() -> {
                synchronized (writer) {
                    try {
                        StatusResponse st = controller.getStatus();
                        Map<String, Object> tick = new LinkedHashMap<>();
                        tick.put("timestamp", System.currentTimeMillis());
                        tick.put("pps", st.getCurrentPps());
                        tick.put("threshold", st.getThresholdPps());
                        tick.put("anomalous", st.isAnomalous());
                        tick.put("monitoringMode", st.getMonitoringMode());
                        tick.put("captureInProgress", st.isCaptureInProgress());
                        tick.put("cooldownActive", st.isCooldownActive());
                        tick.put("selectedInterface", st.getSelectedInterface());
                        tick.put("interfaceDescription", st.getInterfaceDescription());

                        String json = mapper.writeValueAsString(tick);
                        writer.print("event: rate\ndata: " + json + "\n\n");
                        writer.flush();
                    } catch (Exception e) {
                        // Client disconnected
                    }
                }
            }, 1000, 1000, TimeUnit.MILLISECONDS);

            // Wait until client disconnects
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    Thread.sleep(2000);
                    // Heartbeat ping to check connection
                    synchronized (writer) {
                        writer.print(": ping\n\n");
                        writer.flush();
                        if (writer.checkError()) {
                            break; // disconnected
                        }
                    }
                }
            } catch (InterruptedException ignored) {
            } finally {
                ticker.cancel(true);
                controller.removeDetectionListener(detectionConsumer);
                controller.removeSseEventListener(sseEventConsumer);
                try {
                    exchange.close();
                } catch (Exception ignored) {}
            }
        }
    }

    public static void main(String[] args) {
        int serverPort = DEFAULT_PORT;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                serverPort = Integer.parseInt(args[++i]);
            }
        }

        try {
            SpinServer server = new SpinServer(serverPort);
            server.start();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("[*] Shutting down SPIN-IDS Server...");
                server.stop();
            }));

            System.out.println("[*] SPIN-IDS Server running. Press Ctrl+C to terminate.");
        } catch (Exception e) {
            System.err.println("[-] Failed to start SPIN-IDS Server: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
