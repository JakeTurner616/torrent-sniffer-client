package org.serverboi.socket;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SocketServer {

    private final String bindIp;
    private final int port;
    private final String serverName;
    private ServerSocket serverSocket;
    private volatile boolean running = false;
    private Thread acceptThread;
    private final ExecutorService clientExecutor = Executors.newCachedThreadPool();
    private final List<Socket> clients = Collections.synchronizedList(new ArrayList<>());

    public SocketServer(String bindIp, int port, String serverName) {
        this.bindIp = bindIp;
        this.port = port;
        this.serverName = serverName;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket();
        serverSocket.bind(new InetSocketAddress(bindIp, port));
        running = true;
        acceptThread = new Thread(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    clients.add(client);
                    // Optionally, you can handle per-client input/output here
                    clientExecutor.submit(() -> {
                        // For now, we simply keep the connection open.
                        try {
                            // Block until the client disconnects.
                            client.getInputStream().read();
                        } catch (IOException ex) {
                            // Client disconnected
                        }
                    });
                } catch (IOException e) {
                    if (running) {
                        e.printStackTrace();
                    }
                }
            }
        });
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        // Close all clients.
        synchronized (clients) {
            for (Socket client : clients) {
                try {
                    client.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            clients.clear();
        }
        clientExecutor.shutdownNow();
    }

    /**
     * Broadcasts a message to all connected clients. The message is prefixed with the server name.
     */
    public void broadcast(String message) {
        String fullMessage = "[" + serverName + "] " + message + "\n";
        byte[] data = fullMessage.getBytes();
        synchronized (clients) {
            Iterator<Socket> it = clients.iterator();
            while (it.hasNext()) {
                Socket client = it.next();
                try {
                    OutputStream os = client.getOutputStream();
                    os.write(data);
                    os.flush();
                } catch (IOException e) {
                    try {
                        client.close();
                    } catch (IOException ex) {
                        // Ignore
                    }
                    it.remove();
                }
            }
        }
    }
}
