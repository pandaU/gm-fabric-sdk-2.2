package org.whu.gmssl.sun.security.ssl;

import java.security.*;

public class GMJsse extends Provider {

    public static final String NAME = "GMJSSE";
    public static final String GMSSLv10 = "GMSSLv1.0";
    public static final String GMSSLv11 = "GMSSLv1.1";

    private static final long serialVersionUID = 3231825739635378734L;

    private static String info = "Sun JSSE provider" +
            "(PKCS12, SunX509/PKIX key/trust factories, " +
            "SSLv3/TLSv1/TLSv1.1/TLSv1.2)";

    private static String fipsInfo =
            "Sun GMJsse provider (FIPS mode, crypto provider ";

    // tri-valued flag:
    // null  := no final decision made
    // false := data structures initialized in non-FIPS mode
    // true  := data structures initialized in FIPS mode
    private static Boolean fips;

    // the FIPS certificate crypto provider that we use to perform all crypto
    // operations. null in non-FIPS mode
    static Provider cryptoProvider;

    protected static synchronized boolean isFIPS() {
        if (fips == null) {
            fips = false;
        }
        return fips;
    }

    // ensure we can use FIPS mode using the specified crypto provider.
    // enable FIPS mode if not already enabled.
    private static synchronized void ensureFIPS(Provider p) {
        if (fips == null) {
            fips = true;
            cryptoProvider = p;
        } else {
            if (fips == false) {
                throw new ProviderException
                        ("SunJSSE already initialized in non-FIPS mode");
            }
            if (cryptoProvider != p) {
                throw new ProviderException
                        ("SunJSSE already initialized with FIPS crypto provider "
                                + cryptoProvider);
            }
        }
    }

    // standard constructor
    protected GMJsse() {
        super("GMJSSE", 1.8d, info);
        subclassCheck();
        if (Boolean.TRUE.equals(fips)) {
            throw new ProviderException
                    ("GMJSSE is already initialized in FIPS mode");
        }
        registerAlgorithms(false);
    }

    // preferred constructor to enable FIPS mode at runtime
    protected GMJsse(Provider cryptoProvider){
        this(checkNull(cryptoProvider), cryptoProvider.getName());
    }

    // constructor to enable FIPS mode from java.security file
    protected GMJsse(String cryptoProvider){
        this(null, checkNull(cryptoProvider));
    }

    private static <T> T checkNull(T t) {
        if (t == null) {
            throw new ProviderException("cryptoProvider must not be null");
        }
        return t;
    }

    private GMJsse(Provider cryptoProvider,
                   String providerName) {
        super("GMJsse", 1.8d, fipsInfo + providerName + ")");
        subclassCheck();
        if (cryptoProvider == null) {
            // Calling Security.getProvider() will cause other providers to be
            // loaded. That is not good but unavoidable here.
            cryptoProvider = Security.getProvider(providerName);
            if (cryptoProvider == null) {
                throw new ProviderException
                        ("Crypto provider not installed: " + providerName);
            }
        }
        ensureFIPS(cryptoProvider);
        registerAlgorithms(true);
    }

    private void registerAlgorithms(final boolean isfips) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                doRegister(isfips);
                return null;
            }
        });
    }

    private void doRegister(boolean isfips) {
        if (!isfips) {
            put("KeyFactory.RSA",
                    "sun.security.rsa.RSAKeyFactory");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.1", "RSA");

            put("KeyPairGenerator.RSA",
                    "sun.security.rsa.RSAKeyPairGenerator");
            put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyPairGenerator.OID.1.2.840.113549.1.1", "RSA");

            put("Signature.MD2withRSA",
                    "sun.security.rsa.RSASignature$MD2withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.2", "MD2withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.2",
                    "MD2withRSA");

            put("Signature.MD5withRSA",
                    "sun.security.rsa.RSASignature$MD5withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4",
                    "MD5withRSA");

            put("Signature.SHA1withRSA",
                    "sun.security.rsa.RSASignature$SHA1withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5",
                    "SHA1withRSA");
            put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");

        }
        //TODO modify by ringo
        put("Signature.MD5andSHA1withRSA",
                "org.whu.gmssl.sun.security.ssl.RSASignature");

        put("KeyManagerFactory.SunX509",
                "org.whu.gmssl.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        put("KeyManagerFactory.NewSunX509",
                "org.whu.gmssl.sun.security.ssl.KeyManagerFactoryImpl$X509");
        put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");

        put("TrustManagerFactory.SunX509",
                "org.whu.gmssl.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        put("TrustManagerFactory.PKIX",
                "org.whu.gmssl.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
        put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");

        put("SSLContext.TLSv1",
                "org.whu.gmssl.sun.security.ssl.SSLContextImpl$TLS10Context");
        put("SSLContext.TLSv1.1",
                "org.whu.gmssl.sun.security.ssl.SSLContextImpl$TLS11Context");
        put("SSLContext.TLSv1.2",
                "org.whu.gmssl.sun.security.ssl.SSLContextImpl$TLS12Context");
//        put("SSLContext.TLS",
//                "org.whu.gmssl.sun.security.ssl.SSLContextImpl$TLSContext");
        if (!isfips) {
            put("Alg.Alias.SSLContext.SSL", "TLS");
            put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
        }

        put("Alg.Alias.SSLContext.TLS", "GMSSLv1.1");
        put("SSLContext.GMSSLv1.0", "org.whu.gmssl.sun.security.ssl.SSLContextImpl$GMTLS10Context");
        put("SSLContext.GMSSLv1.1", "org.whu.gmssl.sun.security.ssl.SSLContextImpl$GMTLS11Context");

        put("SSLContext.Default",
                "org.whu.gmssl.sun.security.ssl.SSLContextImpl$DefaultSSLContext");

        /*
         * KeyStore
         */
        put("KeyStore.PKCS12",
                "org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi$BCPKCS12KeyStore");

        //TODO modify by ringo
        put("KeyGenerator.SunTlsPrf", "org.whu.gmssl.com.sun.crypto.provider.TlsPrfGenerator$V10");
        put("KeyGenerator.SunTls12Prf", "org.whu.gmssl.com.sun.crypto.provider.TlsPrfGenerator$V12");
        put("KeyGenerator.GBTlsPrf", "org.whu.gmssl.jsse.generator.GBTlsPrfGenerator");
        put("KeyGenerator.SunTlsMasterSecret", "org.whu.gmssl.com.sun.crypto.provider.TlsMasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12MasterSecret", "SunTlsMasterSecret");
        put("KeyGenerator.GBTlsMasterSecret", "org.whu.gmssl.jsse.generator.GBTlsMasterSecretGenerator");
        put("KeyGenerator.SunTlsKeyMaterial", "org.whu.gmssl.com.sun.crypto.provider.TlsKeyMaterialGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial", "SunTlsKeyMaterial");
        put("KeyGenerator.GBTlsKeyMaterial", "org.whu.gmssl.jsse.generator.GBTlsKeyMaterialGenerator");
        put("KeyGenerator.SunTlsRsaPremasterSecret", "org.whu.gmssl.com.sun.crypto.provider.TlsRsaPremasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12RsaPremasterSecret", "SunTlsRsaPremasterSecret");

        put("KeyGenerator.TlsGMPremasterSecret",
                "org.whu.gmssl.sun.security.ssl.premasterSecret.TlsGMPremasterSecretGenerator");

        //TODO X.509
        put("CertificateFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory");
    }

    private void subclassCheck() {
        if (getClass() != org.whu.gmssl.jsse.provider.GMJsseProvider.class) {
            throw new AssertionError("Illegal subclass: " + getClass());
        }
    }

    @Override
    protected final void finalize() throws Throwable {
        // empty
        super.finalize();
    }

}
