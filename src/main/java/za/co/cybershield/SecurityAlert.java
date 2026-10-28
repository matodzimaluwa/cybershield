package za.co.cybershield;

import java.time.Instant;

public record SecurityAlert(
        long id,
        String sourceIp,
        String severity,
        String message,
        Instant createdAt,
        boolean resolved
) {
    public SecurityAlert resolve() {
        return new SecurityAlert(id, sourceIp, severity, message, createdAt, true);
    }
}
