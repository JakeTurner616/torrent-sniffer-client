package org.serverboi.ui;

import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.layout.HBox;
import org.serverboi.monitor.MonitoredDevice;

public class DeviceCell extends ListCell<MonitoredDevice> {

    private final HBox content;
    private final Label nameLabel;
    private final Canvas sparklineCanvas;

    public DeviceCell() {
        nameLabel = new Label();
        sparklineCanvas = new Canvas(100, 20);
        content = new HBox(10, nameLabel, sparklineCanvas);
    }

    @Override
    protected void updateItem(MonitoredDevice item, boolean empty) {
        super.updateItem(item, empty);
        if (empty || item == null) {
            setGraphic(null);
        } else {
            // Use the friendly display name from MonitoredDevice.
            nameLabel.setText(item.toString());
            drawSparkline(item.getSparklineData(), item.getMaxTraffic());
            setGraphic(content);
        }
    }

    private void drawSparkline(int[] data, int maxTraffic) {
        GraphicsContext gc = sparklineCanvas.getGraphicsContext2D();
        gc.clearRect(0, 0, sparklineCanvas.getWidth(), sparklineCanvas.getHeight());
        if (data == null || data.length == 0 || maxTraffic <= 0) {
            return;
        }
        double width = sparklineCanvas.getWidth();
        double height = sparklineCanvas.getHeight();
        double step = width / (data.length - 1);
        gc.beginPath();
        gc.moveTo(0, height - ((double) data[0] / maxTraffic * height));
        for (int i = 1; i < data.length; i++) {
            double x = i * step;
            double y = height - ((double) data[i] / maxTraffic * height);
            gc.lineTo(x, y);
        }
        gc.stroke();
    }
}
