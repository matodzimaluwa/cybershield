package za.co.cybershield;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityMonitorTest {
    @Test
    void raisesHighAlertAfterThreeFailedLoginsFromSameIp() {
        SecurityMonitor monitor = new SecurityMonitor(3);
        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);
        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);
        assertTrue(monitor.alerts().isEmpty());

        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);

        assertEquals(1, monitor.alerts().size());
        assertEquals("HIGH", monitor.alerts().get(0).severity());
    }

    @Test
    void differentIpsAreTrackedSeparately() {
        SecurityMonitor monitor = new SecurityMonitor(3);
        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);
        monitor.record("alex", "192.0.2.11", SecurityEvent.EventType.LOGIN_FAILURE);
        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);
        assertTrue(monitor.alerts().isEmpty());
    }

    @Test
    void rejectsMissingUsername() {
        SecurityMonitor monitor = new SecurityMonitor(3);
        assertThrows(IllegalArgumentException.class,
                () -> monitor.record(" ", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE));
    }

    @Test
    void adminCanResolveAnAlert() {
        SecurityMonitor monitor = new SecurityMonitor(1);
        monitor.record("alex", "192.0.2.10", SecurityEvent.EventType.LOGIN_FAILURE);
        SecurityAlert resolved = monitor.resolveAlert(1);
        assertNotNull(resolved);
        assertTrue(resolved.resolved());
    }
}
