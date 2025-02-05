package org.serverboi.ui;

import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import java.awt.Desktop;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.prefs.Preferences;

public class AdvancedSettingsDialog {

    private final Preferences prefs = Preferences.userNodeForPackage(AdvancedSettingsDialog.class);

    public void show() {
        Stage settingsStage = new Stage();
        settingsStage.setTitle("Advanced Settings");

        // Add the application icon to the sub-window.
        // Ensure that your icon image is available in your resources folder at "/icon.png"
        Image icon = new Image(getClass().getResourceAsStream("/icon.png"));
        settingsStage.getIcons().add(icon);

        // Existing advanced settings section.
        Label infoLabel = new Label("Advanced configuration settings go here:");
        CheckBox debugCheckBox = new CheckBox("Enable Debug Mode");
        debugCheckBox.setSelected(prefs.getBoolean("debugMode", false));

        Label timeoutLabel = new Label("Capture Timeout (ms):");
        Slider timeoutSlider = new Slider(5, 50, prefs.getDouble("captureTimeout", 10));
        timeoutSlider.setShowTickLabels(true);
        timeoutSlider.setShowTickMarks(true);
        timeoutSlider.setMajorTickUnit(10);
        timeoutSlider.setMinorTickCount(5);
        timeoutSlider.setBlockIncrement(1);

        // ── Socket Server Options Section ─────────────────────────────
        TitledPane socketOptionsPane = new TitledPane();
        socketOptionsPane.setText("Socket Server Options");
        GridPane socketGrid = new GridPane();
        socketGrid.setHgap(10);
        socketGrid.setVgap(10);
        socketGrid.setPadding(new Insets(10));

        CheckBox enableSocketServerCheckBox = new CheckBox("Enable Socket Server");
        enableSocketServerCheckBox.setSelected(prefs.getBoolean("socketServer.enabled", false));
        Label ipLabel = new Label("Bind IP:");
        TextField ipField = new TextField(prefs.get("socketServer.ip", "0.0.0.0"));
        Label portLabel = new Label("Port:");
        TextField portField = new TextField(prefs.get("socketServer.port", "5000"));
        Label serverNameLabel = new Label("Server Name:");
        TextField serverNameField = new TextField(prefs.get("socketServer.name", "MySocketServer"));

        socketGrid.add(enableSocketServerCheckBox, 0, 0, 2, 1);
        socketGrid.add(ipLabel, 0, 1);
        socketGrid.add(ipField, 1, 1);
        socketGrid.add(portLabel, 0, 2);
        socketGrid.add(portField, 1, 2);
        socketGrid.add(serverNameLabel, 0, 3);
        socketGrid.add(serverNameField, 1, 3);
        socketOptionsPane.setContent(socketGrid);
        socketOptionsPane.setExpanded(true);

        // ── Capture Log Options Section ─────────────────────────────
        TitledPane captureLogPane = new TitledPane();
        captureLogPane.setText("Capture Log Options");
        GridPane captureGrid = new GridPane();
        captureGrid.setHgap(10);
        captureGrid.setVgap(10);
        captureGrid.setPadding(new Insets(10));

        CheckBox saveCaptureLogCheckBox = new CheckBox("Save Capture Log");
        saveCaptureLogCheckBox.setSelected(prefs.getBoolean("captureLog.enabled", false));
        Label captureLogPathLabel = new Label("Capture Log File Path:");

        // Create a dedicated folder in the system temporary directory.
        File captureDir = new File(System.getProperty("java.io.tmpdir"), "MyCaptureLogs");
        if (!captureDir.exists()) {
            captureDir.mkdirs();
        }
        // Build the default capture log path using the dedicated subfolder.
        String defaultPath = prefs.get("captureLog.path",
                new File(captureDir, "capture.log").getAbsolutePath());
        TextField captureLogPathField = new TextField(defaultPath);

        // Create buttons for clearing and opening the capture file location.
        Button clearCaptureFileButton = new Button("Clear Capture File");
        clearCaptureFileButton.setOnAction(e -> {
            File logFile = new File(captureLogPathField.getText());
            if (logFile.exists() && logFile.isFile()) {
                try (FileWriter fw = new FileWriter(logFile, false)) {
                    // Writing an empty string clears the file.
                    fw.write("");
                } catch (IOException ex) {
                    showAlert("Error", "Could not clear the capture file:\n" + ex.getMessage());
                }
            } else {
                showAlert("Warning", "Capture file does not exist.");
            }
        });

        Button openCaptureFileLocationButton = new Button("Open Capture File Location");
        openCaptureFileLocationButton.setOnAction(e -> {
            File logFile = new File(captureLogPathField.getText());
            File parentDir = logFile.getParentFile();
            if (parentDir != null && java.awt.Desktop.isDesktopSupported()) {
                try {
                    Desktop.getDesktop().open(parentDir);
                } catch (IOException ex) {
                    showAlert("Error", "Could not open file location:\n" + ex.getMessage());
                }
            } else {
                showAlert("Warning", "File location not available.");
            }
        });

        // Place the new buttons in an HBox.
        HBox captureButtonsBox = new HBox(10, clearCaptureFileButton, openCaptureFileLocationButton);

        // Add components to the capture grid.
        captureGrid.add(saveCaptureLogCheckBox, 0, 0, 2, 1);
        captureGrid.add(captureLogPathLabel, 0, 1);
        captureGrid.add(captureLogPathField, 1, 1);
        captureGrid.add(captureButtonsBox, 0, 2, 2, 1);
        captureLogPane.setContent(captureGrid);
        captureLogPane.setExpanded(true);

        // ── UI Console Options Section ─────────────────────────────
        TitledPane uiConsolePane = new TitledPane();
        uiConsolePane.setText("UI Console Options");
        GridPane uiConsoleGrid = new GridPane();
        uiConsoleGrid.setHgap(10);
        uiConsoleGrid.setVgap(10);
        uiConsoleGrid.setPadding(new Insets(10));

        Label maxLogSizeLabel = new Label("Max Log Size (MB):");
        // Default is 25 MB.
        TextField maxLogSizeField = new TextField(Double.toString(prefs.getDouble("ui.console.maxsize", 25.0)));
        uiConsoleGrid.add(maxLogSizeLabel, 0, 0);
        uiConsoleGrid.add(maxLogSizeField, 1, 0);
        uiConsolePane.setContent(uiConsoleGrid);
        uiConsolePane.setExpanded(true);

        // ── Save Button ─────────────────────────────
        Button saveButton = new Button("Save Settings");
        saveButton.setOnAction(e -> {
            // Save basic settings.
            prefs.putBoolean("debugMode", debugCheckBox.isSelected());
            prefs.putDouble("captureTimeout", timeoutSlider.getValue());

            // Save socket server options.
            prefs.putBoolean("socketServer.enabled", enableSocketServerCheckBox.isSelected());
            prefs.put("socketServer.ip", ipField.getText());
            prefs.put("socketServer.port", portField.getText());
            prefs.put("socketServer.name", serverNameField.getText());

            // Save capture log options.
            prefs.putBoolean("captureLog.enabled", saveCaptureLogCheckBox.isSelected());
            prefs.put("captureLog.path", captureLogPathField.getText());

            // Save UI console options.
            try {
                double maxSize = Double.parseDouble(maxLogSizeField.getText());
                prefs.putDouble("ui.console.maxsize", maxSize);
            } catch (NumberFormatException ex) {
                // If parsing fails, revert to the default.
                prefs.putDouble("ui.console.maxsize", 25.0);
            }

            settingsStage.close();
        });

        VBox settingsBox = new VBox(10, infoLabel, debugCheckBox, timeoutLabel, timeoutSlider,
                socketOptionsPane, captureLogPane, uiConsolePane, saveButton);
        settingsBox.setPadding(new Insets(10));

        Scene scene = new Scene(settingsBox, 350, 600);
        settingsStage.setScene(scene);
        settingsStage.show();
    }

    /**
     * A helper method to show alerts.
     *
     * @param title   the title of the alert dialog.
     * @param message the message to display.
     */
    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
