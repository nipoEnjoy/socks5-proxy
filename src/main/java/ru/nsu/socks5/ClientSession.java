package ru.nsu.socks5;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

public class ClientSession {
    public static final int BUFFER_SIZE = 4096;

    public enum State {
        WAITING_FOR_AUTH_METHODS,
        WAITING_FOR_REQUEST,
        WAITING_FOR_DNS_RESPONSE,
        CONNECTING_TO_TARGET,
        ESTABLISHED
    }

    private State currentState = State.WAITING_FOR_AUTH_METHODS;
    private final SocketChannel clientChannel;
    private SocketChannel targetChannel;
    private final Selector selector;

    private ByteBuffer authBuffer;
    private ByteBuffer requestBuffer;
    private ByteBuffer pendingClientData; // While processing DNS

    private String targetDomain;
    private int targetPort;

    private final List<ByteBuffer> pendingWritesToClient = new ArrayList<>();
    private final List<ByteBuffer> pendingWritesToTarget = new ArrayList<>();

    private final Socks5Proxy proxy;

    public ClientSession(SocketChannel clientChannel, Selector selector, Socks5Proxy proxy) {
        this.clientChannel = clientChannel;
        this.selector = selector;
        this.proxy = proxy;
        this.authBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        this.requestBuffer = ByteBuffer.allocate(BUFFER_SIZE);
    }

    public void processData(ByteBuffer data) throws IOException {
        switch (currentState) {
            case WAITING_FOR_AUTH_METHODS:
                handleAuth(data);
                break;
            case WAITING_FOR_REQUEST:
                handleRequest(data);
                break;
            case WAITING_FOR_DNS_RESPONSE:
                // Client can already send smth
                if (pendingClientData == null) {
                    pendingClientData = ByteBuffer.allocate(BUFFER_SIZE * 10);
                }
                pendingClientData.put(data);
                System.out.println("Queued client data while waiting for DNS.");
                break;
            case CONNECTING_TO_TARGET:
            case ESTABLISHED:
                if (targetChannel != null && targetChannel.isConnected()) {
                    pendingWritesToTarget.add(data);
                    SelectionKey key = targetChannel.keyFor(selector);
                    if (key != null && key.isValid()) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    }
                }
                break;
        }
    }

    private void handleAuth(ByteBuffer data) throws IOException {
        authBuffer.put(data);
        if (authBuffer.position() >= 2) { // 1 byte for VER and 1 byte for NMETHODS
            authBuffer.flip();
            byte ver = authBuffer.get();
            byte nMethods = authBuffer.get();
            System.out.println("Got: " + ver + " " + (int) nMethods);

            if (ver != (byte) 0x05) {
                System.err.println("Invalid SOCKS version in auth: " + ver);
                closeConnection();
                return;
            }

            if (authBuffer.remaining() < nMethods) {
                authBuffer.compact();
                return;
            }

            boolean authMethodFound = false;
            for (int i = 0; i < nMethods; i++) {
                byte method = authBuffer.get();
                System.out.println("Got method: " +  method);
                if (method == (byte) 0x00) {
                    authMethodFound = true;
                }
            }
            authBuffer.compact();

            if (!authMethodFound) {
                byte[] responseBytes = new byte[]{(byte) 0x05, (byte) 0xFF};  // Socks ver 5: 0x05; Deny all methods: 0xFF
                ByteBuffer response = ByteBuffer.wrap(responseBytes);
                clientChannel.write(response);
                System.err.println("No acceptable auth method found by client.");
                closeConnection();
                return;
            }

            // Send chosen method (0x00)
            ByteBuffer response = ByteBuffer.wrap(new byte[]{(byte) 0x05, (byte) 0x00});
            clientChannel.write(response);

            currentState = State.WAITING_FOR_REQUEST;
            System.out.println("Authentication successful, waiting for request.");
        }
    }

    private void handleRequest(ByteBuffer data) throws IOException {
        requestBuffer.put(data);
        if (requestBuffer.position() >= 4) { // 4 bytes for (VER, CMD, RSV, ATYP)
            requestBuffer.flip();
            byte ver = requestBuffer.get();
            byte cmd = requestBuffer.get();
            byte rsv = requestBuffer.get();
            byte addrType = requestBuffer.get();

            if (ver != (byte) 0x05) {
                System.err.println("Invalid SOCKS version in request: " + ver);
                sendSocks5Reply(clientChannel, (byte) 0x01); // General server failure
                closeConnection();
                return;
            }
            if (cmd != (byte) 0x01) { // CONNECT
                System.err.println("Unsupported command: " + cmd);
                sendSocks5Reply(clientChannel, (byte) 0x07); // Command not supported
                closeConnection();
                return;
            }
            if (rsv != (byte) 0x00) {
                System.err.println("Invalid reserved byte in request: " + rsv);
                sendSocks5Reply(clientChannel, (byte) 0x01); // General server failure
                closeConnection();
                return;
            }

            InetSocketAddress targetAddr = null;
            // IPv4
            if (addrType == (byte) 0x01) {
                if (requestBuffer.remaining() < 6) { // 4 bytes IP + 2 bytes for port
                    requestBuffer.compact();
                    return;
                }
                byte[] ipBytes = new byte[4];
                requestBuffer.get(ipBytes);
                int port = requestBuffer.getShort() & 0xFFFF; // Short should be unsigned (0x000000000000FFFF)
                targetAddr = new InetSocketAddress(java.net.InetAddress.getByAddress(ipBytes), port);
            }
            // Domain name
            else if (addrType == (byte) 0x03) { // Domain name
                if (requestBuffer.remaining() < 1) { // 1 byte for domain length
                    requestBuffer.compact();
                    return;
                }
                byte domainLength = requestBuffer.get();
                if (requestBuffer.remaining() < domainLength + 2) { // 2 bytes for port
                    requestBuffer.compact();
                    return;
                }
                byte[] domainBytes = new byte[domainLength];
                requestBuffer.get(domainBytes);
                int port = requestBuffer.getShort() & 0xFFFF; // Short should be unsigned (0x000000000000FFFF)
                this.targetDomain = new String(domainBytes);
                this.targetPort = port;
                System.out.println("Received request to connect to domain: " + targetDomain + " on port: " + targetPort);
                requestBuffer.compact();

                currentState = State.WAITING_FOR_DNS_RESPONSE;

                try {
                    proxy.queueDnsRequest(targetDomain, this);
                } catch (IOException e) {
                    System.err.println("Failed to send DNS query: " + e.getMessage());
                    sendSocks5Reply(clientChannel, (byte) 0x01); // General server failure
                    closeConnection();
                }
                return;
            }
            // IPv6
            else if (addrType == (byte) 0x04) {
                System.err.println("IPv6 address type not supported: " + addrType);
                sendSocks5Reply(clientChannel, (byte) 0x08); // Address type not supported
                closeConnection();
                return;
            } else {
                System.err.println("Invalid address type in request: " + addrType);
                sendSocks5Reply(clientChannel, (byte) 0x01); // General server failure
                closeConnection();
                return;
            }
            requestBuffer.compact();

            if (targetAddr != null) {
                System.out.println("Connecting to target: " + targetAddr);
                connectToTarget(targetAddr);
            }
        }
    }

    public void handleDnsResponse(Message dnsResponse) throws IOException {
        if (currentState != State.WAITING_FOR_DNS_RESPONSE) {
            System.err.println("Received DNS response in wrong state.");
            return;
        }

        if (dnsResponse.getHeader().getRcode() != Rcode.NOERROR) {
            System.err.println("DNS lookup failed with code: " + dnsResponse.getHeader().getRcode());
            sendSocks5Reply(clientChannel, (byte) 0x04); // Host unreachable
            closeConnection();
            return;
        }

        List<Record> answers = dnsResponse.getSection(Section.ANSWER);
        java.net.InetAddress targetIP = null;
        for (Record record : answers) {
            if (record.getType() == Type.A) {
                ARecord aRecord = (ARecord) record;
                targetIP = aRecord.getAddress();
                break;
            }
        }

        if (targetIP == null) {
            System.err.println("No A record found for domain: " + targetDomain);
            sendSocks5Reply(clientChannel, (byte) 0x04); // Host unreachable
            closeConnection();
            return;
        }

        System.out.println("Resolved domain " + targetDomain + " to IP: " + targetIP.getHostAddress());
        InetSocketAddress targetAddr = new InetSocketAddress(targetIP, targetPort);
        connectToTarget(targetAddr);
    }

    private void connectToTarget(InetSocketAddress targetAddr) throws IOException {
        targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);

        boolean connected;
        try {
            connected = targetChannel.connect(targetAddr);
        } catch (IOException e) {
            System.err.println("Failed to initiate connection to target: " + e.getMessage());
            sendSocks5Reply(clientChannel, (byte) 0x05); // Connection refused
            closeConnection();
            return;
        }

        if (connected) {
            System.out.println("Directly connected to target.");
            // Acknowledge to client
            sendSocks5Reply(clientChannel, (byte) 0x00);
            setConnectionEstablished();
        } else {
            // Соединение в процессе, регистрируем канал
            targetChannel.register(selector, SelectionKey.OP_CONNECT, this);
            currentState = State.CONNECTING_TO_TARGET;
            System.out.println("Connection to target in progress...");
        }
    }

    public void sendSocks5Reply(SocketChannel channel, byte rep) throws IOException {
        ByteBuffer reply = ByteBuffer.wrap(new byte[]{
                (byte) 0x05, // VER (Socks5)
                rep,         // REP
                (byte) 0x00, // RSV (always 0)
                (byte) 0x01, // ATYP (IPv4)
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // BND.ADDR (0.0.0.0)
                (byte) 0x00, (byte) 0x00  // BND.PORT (0)
        });
        channel.write(reply);
    }

    public void setConnectionEstablished() throws IOException {
        currentState = State.ESTABLISHED;
        SelectionKey clientKey = clientChannel.keyFor(selector);
        SelectionKey targetKey = targetChannel.keyFor(selector);

        if (clientKey != null && clientKey.isValid()) {
            clientKey.interestOps(SelectionKey.OP_READ);
        }
        if (targetKey != null && targetKey.isValid()) {
            targetKey.interestOps(SelectionKey.OP_READ);
        }

        // If already got some data from client, send it to target
        if (pendingClientData != null && pendingClientData.position() > 0) {
            pendingClientData.flip();
            ByteBuffer dataToWrite = ByteBuffer.allocate(pendingClientData.remaining());
            dataToWrite.put(pendingClientData);
            dataToWrite.flip();
            pendingWritesToTarget.add(dataToWrite);
            pendingClientData = null;

            if (targetKey != null && targetKey.isValid()) {
                targetKey.interestOps(targetKey.interestOps() | SelectionKey.OP_WRITE);
            }
        }
    }

    public void queueDataForClient(ByteBuffer data) {
        pendingWritesToClient.add(data);
    }

    public void queueDataForTarget(ByteBuffer data) {
        pendingWritesToTarget.add(data);
    }

    public boolean hasPendingWritesToClient() {
        return !pendingWritesToClient.isEmpty();
    }

    public boolean hasPendingWritesToTarget() {
        return !pendingWritesToTarget.isEmpty();
    }

    public SocketChannel getTargetChannel() {
        return targetChannel;
    }

    public void flushPendingWrites(SocketChannel channel) throws IOException {
        List<ByteBuffer> pendingWrites;
        if (channel == clientChannel) {
            pendingWrites = pendingWritesToClient;
        } else if (channel == targetChannel) {
            pendingWrites = pendingWritesToTarget;
        } else {
            return;  // What
        }

        while (!pendingWrites.isEmpty()) {
            ByteBuffer buffer = pendingWrites.getFirst();
            int bytesWritten = channel.write(buffer);
            if (bytesWritten == -1) {
                closeConnection();
                return;
            }
            if (buffer.hasRemaining()) {
                break;
            } else {
                pendingWrites.removeFirst(); // Moving to next
            }
        }
    }

    public boolean hasPendingWrites() {
        return hasPendingWritesToClient() || hasPendingWritesToTarget();
    }

    public SocketChannel getClientAttachment() {
        return clientChannel;
    }

    public Object getTargetAttachment() {
        return targetChannel;
    }

    private void closeConnection() throws IOException {
        try {
            if (clientChannel != null) clientChannel.close();
        } catch (IOException ignore) {}
        try {
            if (targetChannel != null) targetChannel.close();
        } catch (IOException ignore) {}
    }
}