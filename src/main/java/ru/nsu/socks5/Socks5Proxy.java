package ru.nsu.socks5;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class Socks5Proxy {
    private static final int DEFAULT_DNS_PORT = 53;
    private static final String DEFAULT_DNS_SERVER = "1.1.1.1";
    private static final int DNS_BUFFER_SIZE = 512;

    private final int proxyPort;
    private Selector selector;
    private ServerSocketChannel serverChannel;
    private DatagramChannel dnsChannel;
    private final Map<Integer, ClientSession> dnsPendingRequests = new ConcurrentHashMap<>();
    private final Map<SocketChannel, ClientSession> activeSessions = new ConcurrentHashMap<>();
    private final AtomicBoolean shutdownRequested = new AtomicBoolean(false);

    public Socks5Proxy(int port) {
        this.proxyPort = port;
    }

    public void startProxy() throws IOException {
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));  // Signal handler

        selector = Selector.open();

        serverChannel = setupServerChannel();
        dnsChannel = setupDnsChannel();

        // Main loop
        while (!shutdownRequested.get()) {
            selector.select();  // Blocks

            Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
            while (keyIterator.hasNext()) {
                SelectionKey key = keyIterator.next();
                keyIterator.remove();
                handleSelectorKey(key);
            }
        }

        shutdown();
    }

    private void handleSelectorKey(SelectionKey key) throws IOException {
        if (!key.isValid()) {
            return;
        }

        if (key.isAcceptable()) {
            handleAccept();
        } else if (key.isReadable()) {
            if (key.channel() == dnsChannel) {
                handleDnsRead();
            } else {
                handleRead((SocketChannel) key.channel());
            }
        } else if (key.isWritable()) {
            handleWrite((SocketChannel) key.channel());
        } else if (key.isConnectable()) {
            handleConnect((SocketChannel) key.channel());
        }
    }

    // TCP channel
    private ServerSocketChannel setupServerChannel() throws IOException {
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(new InetSocketAddress(proxyPort));
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);

        System.out.println("SOCKS5 Proxy started on port " + proxyPort);
        return serverChannel;
    }

    // UDP channel
    private DatagramChannel setupDnsChannel() throws IOException {
        DatagramChannel dnsChannel = DatagramChannel.open();
        dnsChannel.configureBlocking(false);
        dnsChannel.connect(new InetSocketAddress(DEFAULT_DNS_SERVER, DEFAULT_DNS_PORT));
        dnsChannel.register(selector, SelectionKey.OP_READ);

        System.out.println("DNS channel initialized for " + DEFAULT_DNS_SERVER + ":" + DEFAULT_DNS_PORT);
        return dnsChannel;
    }

    private void shutdown() {
        System.out.println("Shutting down SOCKS5 Proxy...");
        shutdownRequested.set(true);

        if (selector != null) {
            selector.wakeup();
        }

        for (SocketChannel clientChannel : activeSessions.keySet()) {
            closeConnection(clientChannel);
        }

        try {
            if (serverChannel != null) serverChannel.close();
            System.out.println("Server channel closed.");
        } catch (IOException e) {
            System.err.println("Error closing server channel: " + e.getMessage());
        }

        try {
            if (dnsChannel != null) dnsChannel.close();
            System.out.println("DNS channel closed.");
        } catch (IOException e) {
            System.err.println("Error closing DNS channel: " + e.getMessage());
        }

        try {
            if (selector != null) selector.close();
            System.out.println("Selector closed.");
        } catch (IOException e) {
            System.err.println("Error closing selector: " + e.getMessage());
        }

        System.out.println("SOCKS5 Proxy shutdown complete.");
    }

    private void handleAccept() throws IOException {
        SocketChannel clientChannel = serverChannel.accept();
        if (clientChannel != null) {
            clientChannel.configureBlocking(false);
            SelectionKey clientKey = clientChannel.register(selector, SelectionKey.OP_READ);

            ClientSession session = new ClientSession(clientChannel, selector, this);
            clientKey.attach(session);

            activeSessions.put(clientChannel, session);
            System.out.println("handleAccept: Added clientChannel( " + clientChannel.toString() + ") to activeConnections(" + activeSessions.toString() + ")");
            System.out.println("New client connection accepted.");
        }
    }

    private void handleRead(SocketChannel clientChannel) throws IOException {
        System.out.println("handleRead: " + clientChannel);

        ClientSession session = null;
        boolean isClient = true;

        if (activeSessions.containsKey(clientChannel)) {
            session = activeSessions.get(clientChannel);
            isClient = true;
        } else {
            SelectionKey key = clientChannel.keyFor(selector);
            if (key != null && key.attachment() instanceof ClientSession) {
                session = (ClientSession) key.attachment();
                isClient = false;
            }
        }

        if (session == null) {
            System.err.println("No connection found for read channel, closing: " + clientChannel);
            closeConnection(null, clientChannel);
            return;
        }

        ByteBuffer buffer = ByteBuffer.allocate(ClientSession.BUFFER_SIZE);
        int bytesRead;
        try {
            bytesRead = clientChannel.read(buffer);
        } catch (IOException e) {
            System.err.println("Read error: " + e.getMessage());
            closeConnection(isClient ? clientChannel : null, isClient ? null : clientChannel);
            return;
        }

        if (bytesRead == -1) {
            closeConnection(isClient ? clientChannel : null, isClient ? null : clientChannel);
            return;
        }

        if (bytesRead > 0) {
            buffer.flip();
            if (isClient) {
                session.processData(buffer);
            } else {
                session.queueDataForClient(buffer);
                SelectionKey clientKey = session.getClientAttachment().keyFor(selector);
                if (clientKey != null && clientKey.isValid()) {
                    clientKey.interestOps(clientKey.interestOps() | SelectionKey.OP_WRITE);
                }
            }
        }
    }

    private void handleWrite(SocketChannel channel) throws IOException {
        System.out.println("handleWrite: " + channel);

        SelectionKey key = channel.keyFor(selector);
        if (key == null || !key.isValid()) {
            System.err.println("No valid selection key for write channel.");
            closeConnection(null, channel);
            return;
        }

        ClientSession session = (ClientSession) key.attachment();
        if (session == null) {
            System.err.println("No ClientConnection attached to write channel key.");
            closeConnection(null, channel);
            return;
        }

        try {
            session.flushPendingWrites(channel);
        } catch (IOException e) {
            System.err.println("Error flushing pending writes: " + e.getMessage());
            closeConnection(session.getClientAttachment(), session.getTargetChannel());
            return;
        }

        if (session.hasPendingWritesToClient() && channel == session.getClientAttachment()) {
            key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
        } else if (session.hasPendingWritesToTarget() && channel == session.getTargetChannel()) {
            key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
        } else {
            key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
        }
    }

    private void handleConnect(SocketChannel targetChannel) throws IOException {
        System.out.println("handleConnect: " + targetChannel);
        System.out.println("handleAccept: activeConnections(" + activeSessions.toString() + ")");

        SelectionKey key = targetChannel.keyFor(selector);
        if (key == null || !key.isValid()) {
            System.err.println("No valid selection key for target channel");
            closeConnection(null, targetChannel);
            return;
        }

        ClientSession session = (ClientSession) key.attachment();
        if (session == null) {
            System.err.println("No ClientConnection attached to target channel key");
            closeConnection(null, targetChannel);
            return;
        }

        // Checking connection status
        boolean connected;
        try {
            connected = targetChannel.finishConnect();
        } catch (IOException e) {
            System.err.println("Failed to connect to target: " + e.getMessage());
            session.sendSocks5Reply(session.getClientAttachment(), (byte) 0x05); // Connection refused
            closeConnection(session.getClientAttachment(), targetChannel);
            return;
        }

        if (connected) {
            System.out.println("Successfully connected to target host.");
            session.sendSocks5Reply(session.getClientAttachment(), (byte) 0x00);

            session.setConnectionEstablished();

            SocketChannel clientChannel = (SocketChannel) session.getClientAttachment();
            SelectionKey clientKey = clientChannel.keyFor(selector);
            if (clientKey != null && clientKey.isValid()) {
                clientKey.interestOps(SelectionKey.OP_READ);
            }

            if (key.isValid()) {
                key.interestOps(SelectionKey.OP_READ);
            }
        } else {
            System.out.println("Still connecting... (non-blocking mode)");
        }
    }

    private void handleDnsRead() throws IOException {
        ByteBuffer dnsBuffer = ByteBuffer.allocate(DNS_BUFFER_SIZE);
        InetSocketAddress sender = (InetSocketAddress) dnsChannel.receive(dnsBuffer);
        if (sender != null) {
            dnsBuffer.flip();

            try {
                Message response = new Message(dnsBuffer.array());
                int messageId = response.getHeader().getID();

                ClientSession session = dnsPendingRequests.remove(messageId);
                if (session != null) {
                    System.out.println("Received DNS response for message ID: " + messageId);
                    session.handleDnsResponse(response);
                } else {
                    System.out.println("Received DNS response for unknown message ID: " + messageId);
                }
            } catch (Exception e) {
                System.err.println("Error parsing DNS response: " + e.getMessage());
            }
        }
    }

    public void queueDnsRequest(String domain, ClientSession sessionForCallback) throws IOException {
        Name name = Name.fromString(domain);
        if (!name.isAbsolute()) {
            name = Name.concatenate(name, Name.root);
        }

        Message query = Message.newQuery(Record.newRecord(name, Type.A, DClass.IN));
        byte[] queryBytes = query.toWire();

        dnsPendingRequests.put(query.getHeader().getID(), sessionForCallback);

        ByteBuffer queryBuffer = ByteBuffer.wrap(queryBytes);
        dnsChannel.write(queryBuffer); // Send request
        System.out.println("Sent DNS query for: " + name + " (ID: " + query.getHeader().getID() + ")");
    }

    private void closeConnection(SocketChannel clientChannel) {
        if (clientChannel != null) {
            ClientSession session = activeSessions.remove(clientChannel);
            System.out.println("Removing client channel from connections: " + clientChannel);

            SocketChannel targetChannel = null;
            if (session != null) {
                targetChannel = (SocketChannel) session.getTargetAttachment();
            }

            try {
                clientChannel.close();
                System.out.println("Closed client channel.");
            } catch (IOException e) {
                System.err.println("Error closing client channel: " + e.getMessage());
            }

            if (targetChannel != null && targetChannel.isOpen()) {
                try {
                    targetChannel.close();
                    System.out.println("Closed target channel.");
                } catch (IOException e) {
                    System.err.println("Error closing target channel: " + e.getMessage());
                }
            }
        }
    }

    private void closeConnection(SocketChannel clientChannel, SocketChannel targetChannel) {
        if (clientChannel != null) {
            ClientSession session = activeSessions.remove(clientChannel);
            try {
                clientChannel.close();
                System.out.println("Closed client channel: " + clientChannel);
            } catch (IOException e) {
                System.err.println("Error closing client channel: " + e.getMessage());
            }

            if (session != null && session.getTargetChannel() != null) {
                try {
                    session.getTargetChannel().close();
                    System.out.println("Closed target channel: " + session.getTargetChannel());
                } catch (IOException e) {
                    System.err.println("Error closing target channel: " + e.getMessage());
                }
            }
        } else if (targetChannel != null) {
            try {
                targetChannel.close();
                System.out.println("Closed target channel: " + targetChannel);
            } catch (IOException e) {
                System.err.println("Error closing target channel: " + e.getMessage());
            }
        }
    }
}
