package za.co.cybershield;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

public class SecurityMonitor {
    private final int failureThreshold;
    private final AtomicLong eventIds = new AtomicLong();
    private final AtomicLong alertIds = new AtomicLong();
    private final List<SecurityEvent> events = new ArrayList<>();
    private final List<SecurityAlert> alerts = new ArrayList<>();

    public SecurityMonitor(int failureThreshold) {
        if (failureThreshold < 1) throw new IllegalArgumentException("Failure threshold must be at least 1");
        this.failureThreshold = failureThreshold;
    }

    public synchronized SecurityEvent record(String username, String sourceIp, SecurityEvent.EventType type) {
        validate(username, "username");
        validate(sourceIp, "sourceIp");
        if (type == null) throw new IllegalArgumentException("type is required");

        SecurityEvent event = new SecurityEvent(eventIds.incrementAndGet(), username.trim(), sourceIp.trim(), type, Instant.now());
        events.add(event);

        if (type == SecurityEvent.EventType.LOGIN_SUCCESS) {
            // A successful login clears the current run of failures for this IP.
            return event;
        }

        long failures = events.stream()
                .filter(e -> e.sourceIp().equals(event.sourceIp()))
                .filter(e -> e.type() == SecurityEvent.EventType.LOGIN_FAILURE)
                .filter(e -> e.timestamp().isAfter(Instant.now().minusSeconds(300)))
                .count();
        boolean alreadyOpen = alerts.stream().anyMatch(a -> !a.resolved() && a.sourceIp().equals(event.sourceIp()));
        if (failures >= failureThreshold && !alreadyOpen) {
            alerts.add(new SecurityAlert(alertIds.incrementAndGet(), event.sourceIp(), "HIGH",
                    "Repeated failed login attempts detected for IP " + event.sourceIp(), Instant.now(), false));
        }
        return event;
    }

    public synchronized List<SecurityEvent> events() { return List.copyOf(events); }
    public synchronized List<SecurityAlert> alerts() { return List.copyOf(alerts); }

    public synchronized SecurityAlert resolveAlert(long id) {
        for (int i = 0; i < alerts.size(); i++) {
            SecurityAlert alert = alerts.get(i);
            if (alert.id() == id) {
                SecurityAlert resolved = alert.resolve();
                alerts.set(i, resolved);
                return resolved;
            }
        }
        return null;
    }

    private static void validate(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        if (value.length() > 120) throw new IllegalArgumentException(field + " must be 120 characters or fewer");
    }
}
