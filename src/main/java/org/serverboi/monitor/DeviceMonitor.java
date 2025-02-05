package org.serverboi.monitor;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicInteger;

public class DeviceMonitor implements Runnable {

    private final PcapNetworkInterface device;
    private PcapHandle handle;
    private final AtomicInteger currentCount = new AtomicInteger(0);
    private volatile boolean running = false;
    private final int[] sparklineData = new int[10];
    private int sparkIndex = 0;
    private Timer timer;

    public DeviceMonitor(PcapNetworkInterface device) {
        this.device = device;
    }

    public void start() {
        try {
            handle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch (PcapNativeException e) {
            e.printStackTrace();
            return;
        }
        running = true;
        Thread t = new Thread(this);
        t.setDaemon(true);
        t.start();

        timer = new Timer(true);
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                int count = currentCount.getAndSet(0);
                sparklineData[sparkIndex] = count;
                sparkIndex = (sparkIndex + 1) % sparklineData.length;
            }
        }, 1000, 1000);
    }

    public void stopMonitoring() {
        running = false;
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        if (timer != null) {
            timer.cancel();
        }
    }

    public int[] getSparklineData() {
        return sparklineData;
    }

    public int getMaxTraffic() {
        int max = 1;
        for (int count : sparklineData) {
            if (count > max) {
                max = count;
            }
        }
        return max;
    }

    @Override
    public void run() {
        while (running) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    currentCount.incrementAndGet();
                }
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }
}
