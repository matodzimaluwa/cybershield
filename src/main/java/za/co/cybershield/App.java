package za.co.cybershield;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.UnauthorizedResponse;

import java.util.Map;

public class App {
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "7070"));
        String staffKey = System.getenv().getOrDefault("CYBERSHIELD_STAFF_KEY", "dev-staff-key-change-me");
        String adminKey = System.getenv().getOrDefault("CYBERSHIELD_ADMIN_KEY", "dev-admin-key-change-me");
        createServer(port, staffKey, adminKey, new SecurityMonitor(3)).start(port);
    }

    static Javalin createServer(int port, String staffKey, String adminKey, SecurityMonitor monitor) {
        Javalin app = Javalin.create(config -> config.http.defaultContentType = "application/json");
        app.get("/health", ctx -> ctx.json(Map.of("status", "OK", "service", "CyberShield")));

        app.before("/api/*", ctx -> {
            String supplied = ctx.header("X-API-Key");
            if (supplied == null || !(constantTimeEquals(supplied, staffKey) || constantTimeEquals(supplied, adminKey))) {
                throw new UnauthorizedResponse("Valid API key required");
            }
        });

        app.exception(UnauthorizedResponse.class, (e, ctx) ->
                ctx.status(401).json(Map.of("error", e.getMessage())));

        app.post("/api/events", ctx -> {
            try {
                EventRequest request = JSON.readValue(ctx.body(), EventRequest.class);
                SecurityEvent event = monitor.record(request.username(), request.sourceIp(), request.type());
                ctx.status(201).json(event);
            } catch (IllegalArgumentException e) {
                ctx.status(400).json(Map.of("error", e.getMessage()));
            } catch (Exception e) {
                ctx.status(400).json(Map.of("error", "Invalid event JSON or event type"));
            }
        });
        app.get("/api/events", ctx -> ctx.json(monitor.events()));
        app.get("/api/alerts", ctx -> ctx.json(monitor.alerts()));
        app.post("/api/alerts/{id}/resolve", ctx -> {
            if (!constantTimeEquals(ctx.header("X-API-Key"), adminKey)) {
                ctx.status(403).json(Map.of("error", "Administrator access required"));
                return;
            }
            try {
                long id = Long.parseLong(ctx.pathParam("id"));
                SecurityAlert alert = monitor.resolveAlert(id);
                if (alert == null) ctx.status(404).json(Map.of("error", "Alert not found"));
                else ctx.json(alert);
            } catch (NumberFormatException e) {
                ctx.status(400).json(Map.of("error", "Alert ID must be a number"));
            }
        });
        return app;
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) return false;
        return java.security.MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                right.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public record EventRequest(String username, String sourceIp, SecurityEvent.EventType type) { }
}
