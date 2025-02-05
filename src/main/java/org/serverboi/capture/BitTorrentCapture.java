package org.serverboi.capture;

import org.json.JSONObject;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.prefs.Preferences;

public class BitTorrentCapture {

    private final PcapNetworkInterface device;
    // The log consumer is used for updating the UI.
    private final Consumer<String> logConsumer;
    private PcapHandle handle;
    private volatile boolean capturing = false;
    private Thread captureThread;

    // File-based logging fields. The log file will be HTML-formatted.
    private Path logFilePath;
    private BufferedWriter logFileWriter;

    // Preferences for advanced settings (using the same node as AdvancedSettingsDialog).
    private final Preferences prefs = Preferences.userNodeForPackage(org.serverboi.ui.AdvancedSettingsDialog.class);

    public BitTorrentCapture(PcapNetworkInterface device, Consumer<String> logConsumer) {
        this.device = device;
        this.logConsumer = logConsumer;
    }

    /**
     * Returns the log file path so the UI can read from it.
     */
    public Path getLogFilePath() {
        return logFilePath;
    }

    public void startCapture() {
        try {
            handle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (Exception e) {
            log("<p style='color:red;'>Error opening device for BitTorrent capture: " + e.getMessage() + "</p>");
            return;
        }
        capturing = true;

        // Determine the log file location based on advanced settings.
        boolean saveCaptureLog = prefs.getBoolean("captureLog.enabled", false);
        if (saveCaptureLog) {
        // Create a dedicated folder in the system temporary directory.
        File captureDir = new File(System.getProperty("java.io.tmpdir"), "MyCaptureLogs");
        if (!captureDir.exists()) {
            captureDir.mkdirs();
        }
        // Build the default path using the dedicated folder.
        String defaultPath = Paths.get(captureDir.getAbsolutePath(), "capture.log")
                                .toAbsolutePath().toString();
        String pathStr = prefs.get("captureLog.path", defaultPath);
        logFilePath = Paths.get(pathStr);
        
        // Ensure the file exists (create it if not).
        try {
            if (!Files.exists(logFilePath)) {
                Files.createFile(logFilePath);
            }
        } catch (IOException e) {
            logConsumer.accept("<p style='color:red;'>Failed to create persistent log file: " + e.getMessage() + "</p>");
            return;
        }
    } else {
        try {
            logFilePath = Files.createTempFile("torrent-sniffer-log", ".html");
        } catch (IOException e) {
            logConsumer.accept("<p style='color:red;'>Failed to create temporary log file: " + e.getMessage() + "</p>");
            return;
        }
}


        // Open a writer for the log file.
        try {
            logFileWriter = Files.newBufferedWriter(logFilePath, StandardOpenOption.APPEND);
        } catch (IOException e) {
            logConsumer.accept("<p style='color:red;'>Failed to open log file writer: " + e.getMessage() + "</p>");
            return;
        }

        log("<p style='color:purple;'>Started BitTorrent capture on " + device.getName() + "</p>");
        captureThread = new Thread(() -> {
            while (capturing) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        processPacket(packet);
                    }
                } catch (NotOpenException e) {
                    // Optionally log the error.
                }
            }
        });
        captureThread.setDaemon(true);
        captureThread.start();
    }

    public void stopCapture() {
        capturing = false;
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        if (captureThread != null) {
            try {
                captureThread.join(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        log("<p style='color:red;'>Stopped BitTorrent capture.</p>");
        try {
            if (logFileWriter != null) {
                logFileWriter.close();
            }
        } catch (IOException e) {
            // Optionally log the error.
        }
    }

    private void processPacket(Packet packet) {
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth == null) return;
        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        if (ipV4 == null) return;
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return;

        byte[] payload = (tcp.getPayload() != null) ? tcp.getPayload().getRawData() : new byte[0];
        if (payload.length < 68) return;
        int protoLen = payload[0] & 0xFF;
        if (protoLen != 19) return;
        String protocol = new String(payload, 1, 19, StandardCharsets.UTF_8);
        if (!"BitTorrent protocol".equals(protocol)) return;

        String reserved = bytesToHex(payload, 20, 8);
        String infohash = bytesToHex(payload, 28, 20);
        String peerId = new String(payload, 48, 20, StandardCharsets.UTF_8);

        String srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
        int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
        int dstPort = tcp.getHeader().getDstPort().valueAsInt();

        String formattedSrc = formatIPAddress(srcIp, srcPort);
        String formattedDst = formatIPAddress(dstIp, dstPort);

        String logEntry = "<div style='border:1px solid #ccc; margin:5px; padding:5px;'>" +
                "<p style='font-weight:bold; color:#007700;'>BitTorrent Handshake Detected</p>" +
                "<p><span style='color:blue;'>Infohash:</span> " + infohash + "</p>" +
                "<p><span style='color:green;'>Peer ID:</span> " + peerId + "</p>" +
                "<p><span style='color:orange;'>Source:</span> " + formattedSrc + "</p>" +
                "<p><span style='color:orange;'>Destination:</span> " + formattedDst + "</p>" +
                "<p><span style='color:gray;'>Reserved Bytes:</span> " + reserved + "</p>" +
                "</div>";
        log(logEntry);
    }

    private String bytesToHex(byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < data.length; i++) {
            sb.append(String.format("%02X", data[i]));
        }
        return sb.toString();
    }

    /**
     * Helper method to format an IP address with port.
     * For local addresses, performs a reverse DNS lookup.
     * For public addresses, performs an RDAP lookup.
     */
    private String formatIPAddress(String ip, int port) {
        if (isLocalIP(ip)) {
            try {
                InetAddress addr = InetAddress.getByName(ip);
                String hostname = addr.getCanonicalHostName();
                return hostname + " (" + ip + ":" + port + ")";
            } catch (UnknownHostException e) {
                return ip + ":" + port;
            }
        } else {
            String rdapInfo = getRdapInfo(ip);
            return ip + ":" + port + " (" + rdapInfo + ")";
        }
    }

    /**
     * Returns true if the given IPv4 address is a private (local) address.
     */
    private boolean isLocalIP(String ip) {
        if (ip == null) return false;
        if (ip.startsWith("10.")) return true;
        if (ip.startsWith("192.168.")) return true;
        if (ip.startsWith("172.")) {
            String[] parts = ip.split("\\.");
            if (parts.length >= 2) {
                try {
                    int secondOctet = Integer.parseInt(parts[1]);
                    return (secondOctet >= 16 && secondOctet <= 31);
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        }
        return false;
    }

    /**
     * Performs an RDAP lookup for the given public IP address using the RIPE RDAP API.
     * Implements a retry mechanism with exponential backoff and a 1-second debouncer.
     * Caches the result to avoid repeated requests.
     */
    private String getRdapInfo(String ip) {
        if (rdapCache.containsKey(ip)) {
            return rdapCache.get(ip);
        }
        String rdapUrl = "https://rdap.db.ripe.net/ip/" + ip;
        int attempts = 0;
        final int maxAttempts = 3;
        int backoffMillis = 1000;  // 1-second initial delay
        while (attempts < maxAttempts) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(rdapUrl))
                        .GET()
                        .build();
                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    JSONObject json = new JSONObject(response.body());
                    String country = json.optString("country", "N/A");
                    String name = json.optString("name", "N/A");
                    String result = country + " - " + name;
                    rdapCache.put(ip, result);
                    return result;
                } else {
                    // If not 200, throw an exception to trigger retry.
                    throw new IOException("Non-200 response: " + response.statusCode());
                }
            } catch (Exception e) {
                attempts++;
                if (attempts >= maxAttempts) {
                    return "RDAP lookup failed after " + maxAttempts + " attempts: " + e.getMessage();
                }
                try {
                    Thread.sleep(backoffMillis);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return "RDAP lookup interrupted";
                }
                backoffMillis *= 2;  // Exponential backoff.
            }
        }
        return "RDAP lookup failed";
    }

    // Static cache and HTTP client for RDAP.
    private static final Map<String, String> rdapCache = new HashMap<>();
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /**
     * Writes the given log message (HTML formatted) to the log file.
     * (The UI update is performed by the file tailer.)
     */
    private void log(String message) {
        try {
            if (logFileWriter != null) {
                logFileWriter.write(message);
                logFileWriter.newLine();
                logFileWriter.flush();
            }
        } catch (IOException e) {
            logConsumer.accept("<p style='color:red;'>Failed to write log: " + e.getMessage() + "</p>");
        }
    }
}
