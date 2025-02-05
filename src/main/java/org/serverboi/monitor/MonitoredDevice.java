package org.serverboi.monitor;

import org.pcap4j.core.PcapNetworkInterface;

public class MonitoredDevice {

    private final PcapNetworkInterface device;
    private final DeviceMonitor monitor;
    private final String displayName;

    /**
     * Constructs a MonitoredDevice for a real device.
     *
     * @param device the network interface (should not be null)
     */
    public MonitoredDevice(PcapNetworkInterface device) {
        this.device = device;
        this.monitor = new DeviceMonitor(device);
        String desc = device.getDescription();
        this.displayName = (desc != null && !desc.isEmpty())
                ? desc + " (" + device.getName() + ")"
                : device.getName();
    }

    /**
     * Constructs a MonitoredDevice with a custom display name.
     * This can be used for special options like "All Interfaces" where no underlying device exists.
     *
     * @param device      the network interface (may be null)
     * @param displayName the human-readable display name
     */
    public MonitoredDevice(PcapNetworkInterface device, String displayName) {
        this.device = device;
        this.displayName = displayName;
        // Only create a monitor if a real device is provided.
        this.monitor = (device != null) ? new DeviceMonitor(device) : null;
    }

    public PcapNetworkInterface getDevice() {
        return device;
    }

    public void startMonitoring() {
        if (monitor != null) {
            monitor.start();
        }
    }

    public void stopMonitoring() {
        if (monitor != null) {
            monitor.stopMonitoring();
        }
    }

    public int[] getSparklineData() {
        return (monitor != null) ? monitor.getSparklineData() : new int[0];
    }

    public int getMaxTraffic() {
        return (monitor != null) ? monitor.getMaxTraffic() : 1;
    }

    /**
     * Returns true if this instance represents the special "All Interfaces" option.
     *
     * @return true if no underlying device is set, false otherwise.
     */
    public boolean isAllInterfaces() {
        return device == null;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
