package za.co.cybershield;

import java.time.Instant;

public record SecurityEvent(
        long id,
        String username,
        String sourceIp,
        EventType type,
        Instant timestamp
) {
    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE
    }
}
