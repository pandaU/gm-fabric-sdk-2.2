package org.whu.gmssl.jsse.provider;

import org.whu.gmssl.sun.security.ssl.GMJsse;

import java.security.Provider;

public class GMJsseProvider extends GMJsse {
    private static final long serialVersionUID = 3231825739635378735L;
    public static final String NAME = "GMJSSE";
    public static final String GMSSLv10 = "GMSSLv1.0";
    public static final String GMSSLv11 = "GMSSLv1.1";

    public GMJsseProvider() {
    }

    public GMJsseProvider(Provider var1) {
        super(var1);
    }

    public GMJsseProvider(String var1) {
        super(var1);
    }

    public static synchronized boolean isFIPS() {
        return isFIPS();
    }

    public static synchronized void install() {
    }
}
