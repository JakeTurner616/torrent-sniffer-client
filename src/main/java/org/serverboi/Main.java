package org.serverboi;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.util.Callback;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface;
import org.serverboi.capture.BitTorrentCapture;
import org.serverboi.monitor.MonitoredDevice;
import org.serverboi.ui.AdvancedSettingsDialog;
import org.serverboi.ui.DeviceCell;
import org.serverboi.socket.SocketServer;
import oshi.SystemInfo;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.prefs.Preferences;

public class Main extends Application {

    private ComboBox<MonitoredDevice> deviceComboBox;
    // Use a WebView for HTML-formatted logs.
    private WebView btLogView;
    // HTML header for the log.
    private final String HTML_HEADER = "<html><body style='font-family:Arial; font-size:12px;'>";
    // Accumulated HTML log starting with our header.
    private final StringBuilder htmlLog = new StringBuilder(HTML_HEADER);
    
    // Auto-scroll flag: true means auto-scroll to the bottom when new content arrives.
    private boolean autoScroll = true;
    // ToggleButton for controlling auto-scroll.
    private ToggleButton autoScrollToggle;
    
    private final List<MonitoredDevice> monitoredDevices = new ArrayList<>();
    private BitTorrentCapture btCapture;
    private SocketServer socketServer;
    private Timer scanInfoTimer;
    
    // Fields for file-based UI log updating.
    private ScheduledExecutorService logUpdaterExecutor;
    private long lastKnownPosition = 0;
    private Path tempLogFile; // Will be set when capture starts.
    
    // Maximum UI log size in bytes.
    private long maxLogSizeBytes;


    @Override
    public void start(Stage primaryStage) {
        // Load UI console settings (e.g., max log size).
        loadUIConsoleSettings();
        
        // Create a MenuBar with a Settings menu.
        MenuBar menuBar = new MenuBar();
        Menu settingsMenu = new Menu("Settings");
        MenuItem advancedSettingsItem = new MenuItem("Advanced Settings");
        advancedSettingsItem.setOnAction(e -> new AdvancedSettingsDialog().show());
        settingsMenu.getItems().add(advancedSettingsItem);
        menuBar.getMenus().add(settingsMenu);
        
        // Set up the interface selection UI.
        deviceComboBox = new ComboBox<>();
        deviceComboBox.setPromptText("Select a network interface");
        deviceComboBox.setCellFactory(new Callback<ListView<MonitoredDevice>, ListCell<MonitoredDevice>>() {
            @Override
            public ListCell<MonitoredDevice> call(ListView<MonitoredDevice> listView) {
                return new DeviceCell();
            }
        });
        deviceComboBox.setButtonCell(new DeviceCell());
        
        // Use WebView instead of a TextArea.
        btLogView = new WebView();
        btLogView.setPrefHeight(400);
        btLogView.getEngine().loadContent(htmlLog.toString() + "</body></html>", "text/html");
        // Listen for focus changes on the WebView.
        btLogView.focusedProperty().addListener((obs, wasFocused, isNowFocused) -> {
            // Disable auto-scroll when the WebView is focused.
            autoScroll = !isNowFocused;
        });
        // Intercept hyperlink clicks and open them in the host browser.
        btLogView.getEngine().locationProperty().addListener((obs, oldLoc, newLoc) -> {
            if (newLoc != null && (newLoc.startsWith("http://") || newLoc.startsWith("https://"))) {
                getHostServices().showDocument(newLoc);
                // Reset the WebView's content to our log HTML.
                Platform.runLater(() ->
                    btLogView.getEngine().loadContent(htmlLog.toString() + "</body></html>", "text/html")
                );
            }
        });
        
        // Create the auto-scroll ToggleButton.
        autoScrollToggle = new ToggleButton("Auto-scroll ON");
        autoScrollToggle.setSelected(true);
        autoScrollToggle.setOnAction(e -> {
            autoScroll = autoScrollToggle.isSelected();
            autoScrollToggle.setText(autoScroll ? "Auto-scroll ON" : "Auto-scroll OFF");
        });
        
        Label topLabel = new Label("Choose Interface (sparkline shows overall traffic):");
        VBox topBox = new VBox(5, topLabel, deviceComboBox);
        topBox.setStyle("-fx-padding: 10;");
        
        Label btLabel = new Label("BitTorrent Capture Log:");
        VBox centerBox = new VBox(5, btLabel, btLogView);
        centerBox.setStyle("-fx-padding: 10;");
        
        // Place the auto-scroll ToggleButton at the bottom.
        HBox bottomBox = new HBox(autoScrollToggle);
        bottomBox.setStyle("-fx-padding: 10; -fx-alignment: center;");
        
        VBox topContainer = new VBox(menuBar, topBox);
        
        BorderPane root = new BorderPane();
        root.setTop(topContainer);
        root.setCenter(centerBox);
        root.setBottom(bottomBox);
        Image icon = new Image(getClass().getResourceAsStream("/skunk.png"));
        primaryStage.getIcons().add(icon);
        Scene scene = new Scene(root, 800, 600);
        
        primaryStage.setTitle("BitTorrent Packet Sniffer");
        primaryStage.setScene(scene);
        primaryStage.show();
        
        // Populate the device list using pcap4j.
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            if (devs == null || devs.isEmpty()) {
                System.err.println("No network interfaces found.");
                Platform.exit();
                return;
            }
            // Build OSHI mapping (keyed by MAC address).
            Map<String, String> friendlyNames = buildFriendlyMapping();
            for (PcapNetworkInterface dev : devs) {
                String key = "";
                if (!dev.getLinkLayerAddresses().isEmpty()) {
                    key = dev.getLinkLayerAddresses().get(0).toString();
                }
                String friendly = friendlyNames.get(key);
                if (friendly == null || friendly.isEmpty()) {
                    String desc = dev.getDescription();
                    friendly = (desc != null && !desc.trim().isEmpty())
                            ? desc + " (" + dev.getName() + ")"
                            : dev.getName();
                }
                monitoredDevices.add(new MonitoredDevice(dev, friendly));
            }
            // Optionally: sort devices by likelihood of BitTorrent traffic.
            monitoredDevices.sort((d1, d2) -> Double.compare(
                    calculateBtLikelihood(d2.getDevice()),
                    calculateBtLikelihood(d1.getDevice())
            ));
            deviceComboBox.setItems(FXCollections.observableArrayList(monitoredDevices));
            deviceComboBox.getSelectionModel().selectFirst();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Start monitoring for sparkline updates.
        monitoredDevices.forEach(MonitoredDevice::startMonitoring);
        
        // When a device is selected, start BitTorrent capture on that device.
        deviceComboBox.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null) {
                if (btCapture != null) {
                    btCapture.stopCapture();
                }
                btCapture = new BitTorrentCapture(newVal.getDevice(),
                        message -> Platform.runLater(() -> appendToHtmlLog(message)));
                btCapture.startCapture();
                tempLogFile = btCapture.getLogFilePath();
                lastKnownPosition = 0;
                if (logUpdaterExecutor != null && !logUpdaterExecutor.isShutdown()) {
                    logUpdaterExecutor.shutdownNow();
                }
                logUpdaterExecutor = Executors.newSingleThreadScheduledExecutor();
                logUpdaterExecutor.scheduleAtFixedRate(this::updateLogFromFile, 0, 1, TimeUnit.SECONDS);
            }
        });
        
        // Initialize the embedded Socket Server (if enabled).
        Preferences prefs = Preferences.userNodeForPackage(AdvancedSettingsDialog.class);
        boolean socketServerEnabled = prefs.getBoolean("socketServer.enabled", false);
        if (socketServerEnabled) {
            String bindIp = prefs.get("socketServer.ip", "0.0.0.0");
            int port = Integer.parseInt(prefs.get("socketServer.port", "5000"));
            String serverName = prefs.get("socketServer.name", "MySocketServer");
            socketServer = new SocketServer(bindIp, port, serverName);
            try {
                socketServer.start();
            } catch (Exception e) {
                System.err.println("Failed to start socket server: " + e.getMessage());
            }
            scanInfoTimer = new Timer(true);
            scanInfoTimer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    StringBuilder scanInfo = new StringBuilder();
                    for (MonitoredDevice md : monitoredDevices) {
                        scanInfo.append(md.toString())
                                .append(" - Traffic: ")
                                .append(Arrays.toString(md.getSparklineData()))
                                .append("\n");
                    }
                    if (socketServer != null) {
                        socketServer.broadcast(scanInfo.toString());
                    }
                }
            }, 0, 2000); // broadcast every 2 seconds
        }
        
        primaryStage.setOnCloseRequest(this::handleCloseRequest);
    }
    
    /**
     * Loads UI console settings (e.g., maximum log size) from preferences.
     */
    private void loadUIConsoleSettings() {
        Preferences prefs = Preferences.userNodeForPackage(AdvancedSettingsDialog.class);
        double maxSizeMB = prefs.getDouble("ui.console.maxsize", 25.0);
        maxLogSizeBytes = (long)(maxSizeMB * 1024 * 1024);
    }
    
    /**
     * Uses OSHI to build a mapping from a network interface's MAC address to its friendly display name.
     */
    private Map<String, String> buildFriendlyMapping() {
        Map<String, String> friendlyNames = new HashMap<>();
        try {
            SystemInfo si = new SystemInfo();
            HardwareAbstractionLayer hal = si.getHardware();
            List<NetworkIF> netIfs = hal.getNetworkIFs();
            for (NetworkIF netIF : netIfs) {
                String mac = netIF.getMacaddr();
                if (mac != null && !mac.isEmpty()) {
                    friendlyNames.put(mac, netIF.getDisplayName());
                }
            }
        } catch (Exception e) {
            System.err.println("Error building friendly mapping: " + e.getMessage());
        }
        return friendlyNames;
    }
    
    /**
     * Periodically reads new content from the log file and appends it to the HTML log.
     */
    private void updateLogFromFile() {
        if (tempLogFile == null) {
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(tempLogFile.toFile(), "r")) {
            raf.seek(lastKnownPosition);
            String line;
            StringBuilder newContent = new StringBuilder();
            while ((line = raf.readLine()) != null) {
                newContent.append(line).append("\n");
            }
            lastKnownPosition = raf.getFilePointer();
            if (newContent.length() > 0) {
                Platform.runLater(() -> appendToHtmlLog(newContent.toString()));
            }
        } catch (IOException e) {
            Platform.runLater(() -> appendToHtmlLog("<p style='color:red;'>Error reading log file: " + e.getMessage() + "</p>"));
        }
    }
    
    /**
     * Escapes a string so that it can be safely embedded in a JavaScript double-quoted string literal.
     */
    private String escapeForJavaScript(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "");
    }
    
    /**
     * Appends new HTML content to the document in the WebView without reloading the page.
     * If auto-scroll is enabled, scrolls to the bottom.
     * Also ensures that the in-memory log does not exceed the maximum allowed size.
     *
     * @param newContent the new HTML content to append.
     */
    private void appendToHtmlLog(String newContent) {
        // Before appending, check if the new total size would exceed our maximum.
        if (htmlLog.length() + newContent.length() > maxLogSizeBytes) {
            int headerLength = HTML_HEADER.length();
            // Current body length is total length minus header.
            int currentBodyLength = htmlLog.length() - headerLength;
            // Remove roughly the oldest half of the body.
            int trimLength = currentBodyLength / 2;
            if (trimLength > 0 && htmlLog.length() > headerLength + trimLength) {
                String trimmedBody = htmlLog.substring(headerLength + trimLength);
                htmlLog.replace(0, htmlLog.length(), HTML_HEADER + trimmedBody);
                // Reload the WebView with the trimmed content.
                btLogView.getEngine().loadContent(htmlLog.toString() + "</body></html>", "text/html");
            }
        }
        
        // Append the new content.
        htmlLog.append(newContent);
        // Escape new content for safe DOM insertion.
        String safeContent = escapeForJavaScript(newContent);
        // Append the new content at the end of the document body.
        btLogView.getEngine().executeScript(
            "document.body.insertAdjacentHTML('beforeend', \"" + safeContent + "\");"
        );
        if (autoScroll) {
            // Scroll to the bottom.
            btLogView.getEngine().executeScript("window.scrollTo(0, document.body.scrollHeight);");
        }
    }
    
    /**
     * Handles the window close event by performing cleanup.
     */
    private void handleCloseRequest(WindowEvent event) {
        if (logUpdaterExecutor != null && !logUpdaterExecutor.isShutdown()) {
            logUpdaterExecutor.shutdownNow();
        }
        monitoredDevices.forEach(MonitoredDevice::stopMonitoring);
        if (btCapture != null) {
            btCapture.stopCapture();
        }
        if (socketServer != null) {
            socketServer.stop();
        }
        if (scanInfoTimer != null) {
            scanInfoTimer.cancel();
        }
    
        // Check if persistent logging is disabled before scheduling deletion.
        Preferences prefs = Preferences.userNodeForPackage(AdvancedSettingsDialog.class);
        boolean persistLog = prefs.getBoolean("captureLog.enabled", false);
        if (!persistLog && tempLogFile != null) {
            tempLogFile.toFile().deleteOnExit();
        }
    }
    
    /**
     * A simple heuristic to calculate the likelihood of BitTorrent traffic on an interface.
     */
    private double calculateBtLikelihood(PcapNetworkInterface dev) {
        double score = 1.0;
        String name = dev.getName().toLowerCase();
        String description = (dev.getDescription() != null ? dev.getDescription() : "").toLowerCase();
        if (name.contains("eth") || description.contains("ethernet")) {
            score += 1.0;
        }
        if (name.contains("wifi") || description.contains("wi-fi") || description.contains("wireless")) {
            score += 0.5;
        }
        if (dev.getAddresses() != null && dev.getAddresses().size() > 1) {
            score += 0.5;
        }
        return score;
    }
    
    @Override
    public void stop() throws Exception {
        super.stop();
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}
