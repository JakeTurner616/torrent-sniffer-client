# BitTorrent Sniffer Client

**Summary:**  
A modular JavaFX application that monitors network interfaces for BitTorrent handshake traffic, displays real-time traffic data, and (optionally) runs an embedded socket server to broadcast scan information. Advanced settings—including socket server options and various logging preferences—are persisted using Java Preferences.

---

## Project Structure

- **Main.java**  
  *Entry point.*  
  Sets up the JavaFX UI, initializes network interface scanning/monitoring, and manages the BitTorrent capture and optional socket server.

- **org.serverboi.capture.BitTorrentCapture.java**  
  Handles packet capture using pcap4j, processes BitTorrent handshake packets, and logs events via a callback mechanism.  
  **Recent Updates:**  
  - Writes capture logs to a file (either persistent or temporary) rather than storing them solely in memory.
  - Uses a dedicated subfolder (e.g., `MyCaptureLogs` inside the system temporary directory) when persistent logging is enabled.

- **org.serverboi.monitor.MonitoredDevice.java**  
  Wraps a `PcapNetworkInterface` and its associated monitoring logic.

- **org.serverboi.monitor.DeviceMonitor.java**  
  Continuously monitors network traffic on an interface, updating sparkline data used by the UI.

- **org.serverboi.ui.DeviceCell.java**  
  Custom ListCell for the device selection ComboBox; displays device names and sparkline traffic information.

- **org.serverboi.ui.AdvancedSettingsDialog.java**  
  Provides an advanced settings dialog for configuring application options, including:
  - Debug mode and capture timeout.
  - Socket server options (enable/disable, bind IP, port, server name).
  - Capture log options with:
    - Choice to persist capture logs.
    - A configurable capture log file path (defaulting to a file in the subfolder `MyCaptureLogs` in the system temporary directory).
    - Buttons to clear the capture file and open its containing folder.
  - UI console options with a configurable maximum log size (default 25 MB) to limit the in-memory log.
  - The settings dialog window now displays an application icon loaded from the classpath.

- **org.serverboi.socket.SocketServer.java**  
  Implements an embedded socket server that listens for client connections and broadcasts scan data (prefixed with a humanized server name) in real time.

---

## Key Specifications

- **Modularity:**  
  Each functional area (capture, monitoring, UI, socket server) is encapsulated in its own package/module to ease maintenance and future extension.

- **Real-Time Data:**  
  Sparkline data is updated via a timer in `DeviceMonitor`. A separate timer in `Main` broadcasts aggregated scan info to connected socket clients every few seconds.

- **Configurable & Persistent:**  
  Advanced settings (including socket server options and logging preferences) use Java’s Preferences API to persist configurations across restarts.

- **Socket Server Identification:**  
  All broadcast messages are prefixed with a humanized server name, allowing clients to differentiate between multiple server instances.

- **Disk-Based Logging:**  
  Instead of retaining all log data in memory, capture logs are written to a file on disk. When a file-based log is used, the UI periodically reads new entries from the file. Additionally, the in-memory log displayed in the UI is limited to a configurable maximum size (defaulting to 25 MB), with older entries trimmed as new ones arrive.

---

## Intended Development Standards

- **Modular Design:**  
  Separate responsibilities into capture, monitoring, UI, and socket server components.

- **Real-Time Monitoring & Broadcast:**  
  Integration of both visual (JavaFX UI) and network (socket server) components.

- **Persistent Advanced Settings:**  
  Use of Preferences for configuration persistence.

- **Extensibility:**  
  The codebase is structured to allow easy expansion (e.g., new capture filters, additional UI components, or enhanced socket server features).

- **Self-Documenting:**  
  The codebase documentation is written at the code level; all code objects are highly self descriptive and include comments.

---

## Recent Enhancements

- **Disk-Based Capture Logging:**  
  The application now writes capture logs to disk rather than keeping all log data in memory. This is especially useful for long-running sessions or high-traffic scenarios. When persistent logging is enabled, logs are saved in a dedicated subfolder (`MyCaptureLogs`) inside the system temporary directory by default.

- **Advanced Logging Options:**  
  The advanced settings dialog has been updated to include:
  - **Clear Capture File:** A button that clears the current capture log file.
  - **Open Capture File Location:** A button that opens the folder containing the capture log file in the system file explorer.
  - **Configurable Log File Path:** Users can specify a custom file path for capture logs, with a default pointing to the dedicated subfolder.
  - **Configurable UI Console Log Size:** The maximum in-memory log size for the UI console is configurable (default is 25 MB), ensuring that older log entries are trimmed to conserve memory.

- **Enhanced User Interface:**  
  The advanced settings dialog now displays an application icon (loaded from the classpath) to improve visual branding and consistency.

---
