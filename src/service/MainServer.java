package service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.*;
import core.AES_service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class MainServer {
    private static final String SERVER_API_KEY = loadAPIkey();
    private static final ConcurrentHashMap<String, RequestWindow> RATE_LIMIT_MAP = new ConcurrentHashMap<>();

    private static final int RATE_LIMIT_MAX = 20;
    private static final long RATE_LIMIT_WINDOW_MS = 60_000;

    public static void main(String[] args) {

        String portstr = System.getenv("PORT");
        if(portstr == null){
            portstr = "8080";
        }

        try {
            int port = Integer.parseInt(portstr);

            InetSocketAddress address = new InetSocketAddress(port);

            HttpServer server = HttpServer.create(address, 0);

            ExecutorService threadpool = Executors.newFixedThreadPool(12);
            server.setExecutor(threadpool);

            encryptHandler enchandler = new encryptHandler();
            decryptHandler dechandler = new decryptHandler();
            healthHandler healthandler = new healthHandler();
            server.createContext("/api/v1/encrypt", new LoggingHandler(new RateLimitHandler(new APIHandler(enchandler))));
            server.createContext("/api/v1/decrypt", new LoggingHandler(new RateLimitHandler(new APIHandler(dechandler))));
            server.createContext("/api/v1/health", new LoggingHandler(healthandler));
            server.start();
            System.out.println("Server Started on " + port + "...");

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Shutting down server and thread pool...");
                server.stop(0);
                threadpool.shutdown();
            }));
        } catch (NumberFormatException e) {
            System.err.println("[STARTUP ERROR] Invalid PORT value");
        }catch (IOException e){
            System.err.println("[STARTUP ERROR] Failed to start server: " + e.getMessage());
        }
    }

    static class RequestWindow {
        int requestCount;
        long windowStartMillis;

//        RequestWindow(int requestCount, long windowLongMillis) {
//            this.requestCount = requestCount;
//            this.windowLongMillis = windowLongMillis;
//        }
    }

    private static String loadAPIkey(){
        String apikey = System.getenv("API_KEY");
        if(apikey == null || apikey.isBlank()){
            throw new RuntimeException("[STARTUP ERROR] Environment variable API_KEY is not set");
        }
        return apikey;
    }

    static class StatusCapture extends HttpExchange{
        private final HttpExchange original;
        private int status = 200;
        StatusCapture(HttpExchange original) {
            this.original = original;
        }
        public int getStatus() {
            return status;
        }

        @Override
        public Headers getRequestHeaders() {
            return original.getRequestHeaders();
        }

        @Override
        public Headers getResponseHeaders() {
            return original.getResponseHeaders();
        }

        @Override
        public URI getRequestURI() {
            return original.getRequestURI();
        }

        @Override
        public String getRequestMethod() {
            return original.getRequestMethod();
        }

        @Override
        public HttpContext getHttpContext() {
            return original.getHttpContext();
        }

        @Override
        public void close() {
            original.close();
        }

        @Override
        public InputStream getRequestBody() {
            return original.getRequestBody();
        }

        @Override
        public OutputStream getResponseBody() {
            return original.getResponseBody();
        }

        @Override
        public void sendResponseHeaders(int rcode, long responseLength) throws IOException {
            this.status = rcode;
            original.sendResponseHeaders(rcode, responseLength);
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            return original.getRemoteAddress();
        }

        @Override
        public int getResponseCode() {
            return status;
        }

        @Override
        public InetSocketAddress getLocalAddress() {
            return original.getLocalAddress();
        }

        @Override
        public String getProtocol() {
            return original.getProtocol();
        }

        @Override
        public Object getAttribute(String name) {
            return original.getAttribute(name);
        }

        @Override
        public void setAttribute(String name, Object value) {
            original.setAttribute(name, value);
        }

        @Override
        public void setStreams(InputStream i, OutputStream o) {
            original.setStreams(i, o);
        }

        @Override
        public HttpPrincipal getPrincipal() {
            return original.getPrincipal();
        }
    }


    static class LoggingHandler implements HttpHandler {
        private final HttpHandler next;

        LoggingHandler(HttpHandler next) {
            this.next = next;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            long start = System.currentTimeMillis();

            StatusCapture wrapped = new StatusCapture(exchange);
            try {
                next.handle(wrapped);
            }catch (Exception e) {
                System.err.printf("[ERROR] %s %s - %s%n", exchange.getRequestMethod(), exchange.getRequestURI().getPath(), e.getClass().getSimpleName());

                if (wrapped.getStatus() == 200) {
                    String response = "Internal server error";
                    byte[] body = response.getBytes(StandardCharsets.UTF_8);

                    wrapped.getResponseHeaders().set("Content-Type", "text/plain");
                    wrapped.sendResponseHeaders(500, body.length);

                    try (OutputStream os = wrapped.getResponseBody()) {
                        os.write(body);
                    }
                }
            }finally {
                long duration = System.currentTimeMillis() - start;

                String ip =  exchange.getRemoteAddress().getAddress().getHostAddress();
                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();

                int status = wrapped.getStatus();

                System.out.printf("[INFO] %s %s %s %d %dms%n", ip, method, path, status, duration);
            }
        }
    }

    static class RateLimitHandler implements HttpHandler {
        private final HttpHandler next;

        RateLimitHandler(HttpHandler next) {
            this.next = next;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String ip = exchange.getRemoteAddress().getAddress().getHostAddress();
            long now = System.currentTimeMillis();
            RequestWindow window = RATE_LIMIT_MAP.get(ip);

            if(window == null){
                RequestWindow newWindow = new RequestWindow();
                newWindow.requestCount = 1;
                newWindow.windowStartMillis = now;

                RATE_LIMIT_MAP.put(ip, newWindow);

                next.handle(exchange);
                return;
            }

            if(now - window.windowStartMillis > RATE_LIMIT_WINDOW_MS){
                window.requestCount = 1;
                window.windowStartMillis = now;
                next.handle(exchange);
                return;
            }

            window.requestCount++;
            if(window.requestCount > RATE_LIMIT_MAX){
                String response = "Too Many Requests";
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(429, response.getBytes(StandardCharsets.UTF_8).length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes(StandardCharsets.UTF_8));
                }
                return;
            }
            next.handle(exchange);
        }
    }

    static class APIHandler implements HttpHandler{
        private final HttpHandler next;
        APIHandler(HttpHandler next) {
            this.next = next;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String api_key = exchange.getRequestHeaders().getFirst("X-API-Key");
            if(api_key == null || !api_key.equals(SERVER_API_KEY)){
                String response = "Forbidden";
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(403, response.getBytes(StandardCharsets.UTF_8).length);

                try(OutputStream os = exchange.getResponseBody()){
                    os.write(response.getBytes(StandardCharsets.UTF_8));
                }
                return;
            }
            next.handle(exchange);
        }
    }

    static class healthHandler implements HttpHandler {
        public void  handle(HttpExchange exchange) throws IOException {
            if(!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                String error_msg = "wrong request method";
                exchange.sendResponseHeaders(405, error_msg.length());
                OutputStream os = exchange.getResponseBody();
                os.write(error_msg.getBytes(StandardCharsets.UTF_8));
                os.close();
            }else{
                String json = "{" + "\"status\":\"UP\"" + "}";
                byte[] json_bytes = json.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, json_bytes.length);

                OutputStream os = exchange.getResponseBody();
                os.write(json_bytes);
                os.close();
            }
        }
    }

    static class encryptHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {

            final long MAX_REQUEST_SIZE = 10 * 1024 * 1024;

            Headers header = exchange.getRequestHeaders();
            String accept = header.getFirst("Accept");
            boolean wantsJson = accept != null && accept.contains("application/json");

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
//                statusCode = 405;
                sendError(exchange, 405, "Method not allowed", wantsJson);
                return;
            }

            String size = header.getFirst("Content-Length");
            if (size != null) {
                try {
                    long content_size = Long.parseLong(size);
                    if (content_size > MAX_REQUEST_SIZE) {
                        sendError(exchange, 413, "Payload too large", wantsJson);
                        return;
                    }
                } catch (NumberFormatException ignored) {}
            }

            String password = header.getFirst("X-Password");
            String extension = header.getFirst("X-Extension");

            if (password == null || password.isEmpty() || extension == null || extension.isEmpty()) {
//                statusCode = 400;
                sendError(exchange, 400, "Missing X-Password or X-Extension", wantsJson);
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            byte[] buffer = new byte[8192];
            int byt;
            long total_read = 0;

            while ((byt = is.read(buffer)) != -1) {

                total_read += byt;

                if (total_read > MAX_REQUEST_SIZE) {
                    sendError(exchange, 413, "Payload too large", wantsJson);
                    return;
                }

                baos.write(buffer, 0, byt);
            }

            byte[] requested_data = baos.toByteArray();
            baos.close();

            try {
                byte[] encrypted_data = AES_service.encrypt(requested_data, password, extension);

                if (wantsJson) {
//                    byte[] encoded_text = AES_service.encoder(encrypted_data);
                    byte[] encoded_text = Base64.getEncoder().encode(encrypted_data);
                    String base64 = new String(encoded_text, StandardCharsets.UTF_8);

                    String json = "{"
                            + "\"status\":\"success\","
                            + "\"data\":\"" + base64 + "\""
                            + "}";

                    byte[] response = json.getBytes(StandardCharsets.UTF_8);

                    exchange.getResponseHeaders().add("Content-Type", "application/json");
//                    statusCode = 200;
                    exchange.sendResponseHeaders(200, response.length);

                    OutputStream os = exchange.getResponseBody();
                    os.write(response);
                    os.close();

                } else {
                    exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
//                    statusCode = 200;
                    exchange.sendResponseHeaders(200, encrypted_data.length);

                    OutputStream os = exchange.getResponseBody();
                    os.write(encrypted_data);
                    os.close();
                }

            } catch (Exception e) {
//                statusCode = 500;
                sendError(exchange, 500, "Encryption Failed", wantsJson);
            }
//            finally {
//                long duration = System.currentTimeMillis() - start;
//
//                System.out.printf("[INFO] %s %s %s %d %dms%n", ip, method, path, statusCode, duration);
//            }
        }

        private void sendError(HttpExchange exchange, int status, String message, boolean wantsJson) throws IOException {

            byte[] response;

            if (wantsJson) {
                String json = "{"
                        + "\"status\":\"error\","
                        + "\"message\":\"" + message + "\""
                        + "}";
                response = json.getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().add("Content-Type", "application/json");
            } else {
                response = message.getBytes(StandardCharsets.UTF_8);
            }

            exchange.sendResponseHeaders(status, response.length);

            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        }
    }
    static class decryptHandler implements HttpHandler {

        private static final long MAX_REQUEST_SIZE = 10 * 1024 * 1024;

        public void handle(HttpExchange exchange) throws IOException {

            Headers headers = exchange.getRequestHeaders();
            String contentType = headers.getFirst("Content-Type");
            String acceptType = headers.getFirst("Accept");

            boolean wantsJson = acceptType != null && acceptType.contains("application/json");

            String size = headers.getFirst("Content-Length");
            if (size != null) {
                try {
                    long content_size = Long.parseLong(size);
                    if (content_size > MAX_REQUEST_SIZE) {
                        sendError(exchange, 413, "Payload too large", wantsJson);
                        return;
                    }
                } catch (NumberFormatException ignored) {}
            }

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendError(exchange, 405, "Method not allowed", wantsJson);
                return;
            }

            String password = headers.getFirst("X-Password");
            if (password == null || password.isEmpty()) {
                sendError(exchange, 400, "Missing X-Password", wantsJson);
                return;
            }

            byte[] requestBytes;
            try (InputStream is = exchange.getRequestBody();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[8192];
                int read;
                long total_bytes = 0;

                while ((read = is.read(buffer)) != -1) {
                    total_bytes += read;
                    if (total_bytes > MAX_REQUEST_SIZE) {
                        sendError(exchange, 413, "Payload too large", wantsJson);
                        return;
                    }
                    baos.write(buffer, 0, read);
                }

                requestBytes = baos.toByteArray();
            }

            if (requestBytes.length == 0) {
                sendError(exchange, 400, "Empty request body", wantsJson);
                return;
            }

            byte[] encryptedBytes;

            try {
                if (contentType != null && contentType.contains("application/json")) {

                    String jsonString = new String(requestBytes, StandardCharsets.UTF_8);

                    Gson gson = new Gson();
                    JsonObject jsonObject = gson.fromJson(jsonString, JsonObject.class);

                    if (!jsonObject.has("data")) {
                        sendError(exchange, 400, "Missing 'data' field", wantsJson);
                        return;
                    }

                    String base64 = jsonObject.get("data").getAsString();

//                  encryptedBytes = AES_service.decoder(base64.getBytes(StandardCharsets.UTF_8));
                    encryptedBytes = Base64.getDecoder().decode(base64.getBytes(StandardCharsets.UTF_8));
                } else {
                    encryptedBytes = requestBytes;
                }
            } catch (Exception e) {
                sendError(exchange, 400, "Invalid JSON or Base64", wantsJson);
                return;
            }

            try {
                AES_service.Decryption_Res result = AES_service.decrypt(encryptedBytes, password);

                byte[] plaintext = result.plainText();
                String extension = result.extension();

                if (wantsJson) {
                    String base64 = java.util.Base64.getEncoder().encodeToString(plaintext);

                    String json = "{"
                            + "\"status\":\"success\","
                            + "\"extension\":\"" + extension + "\","
                            + "\"data\":\"" + base64 + "\""
                            + "}";

                    byte[] response = json.getBytes(StandardCharsets.UTF_8);

                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length);

                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }

                } else {
                    String contentTypeResolved = content_type_resolve(extension);

                    exchange.getResponseHeaders().add("Content-Type", contentTypeResolved);
                    exchange.sendResponseHeaders(200, plaintext.length);

                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(plaintext);
                    }
                }
            } catch (SecurityException e) {
                sendError(exchange, 401, "Wrong password or tampered data", wantsJson);
            } catch (Exception e) {
                sendError(exchange, 500, "Decryption failed", wantsJson);
            }
        }

        private void sendError(HttpExchange exchange, int status, String message, boolean wantsJson) throws IOException {

            byte[] response;

            if (wantsJson) {
                String json = "{"
                        + "\"status\":\"error\","
                        + "\"message\":\"" + message + "\""
                        + "}";

                response = json.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
            } else {
                response = message.getBytes(StandardCharsets.UTF_8);
            }

            exchange.sendResponseHeaders(status, response.length);

            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }
    static String content_type_resolve(String extension){
        String ext = extension.toLowerCase();
        return switch (ext) {
            case "txt" -> "text/plain";
            case "mp4" -> "video/mp4";
            case "png" -> "image/png";
            case "jpg", "jpeg" -> "image/jpeg";
            case "gif" -> "image/gif";
            case "pdf" -> "application/pdf";
            case "mkv" -> "video/mpeg4";
            default -> "application/octet-stream";
        };
    }
}
