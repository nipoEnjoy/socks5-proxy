package ru.nsu.socks5;

import java.io.IOException;

public class Main {
    public static void main(String[] args) {
//        if (args.length != 1) {
//            System.err.println("Usage: java Socks5Proxy <port>");
//            System.exit(1);
//        }

//        int port = Integer.parseInt(args[0]);
        int port = 1081;
        Socks5Proxy proxy = new Socks5Proxy(port);

        try {
            proxy.startProxy();
        } catch (IOException e) {
            System.err.println("Proxy failed to start: " + e.getMessage());
            e.printStackTrace();
        }
    }
}