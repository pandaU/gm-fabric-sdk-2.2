package org.whu.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.X509Certificate;

//TODO modify by ringo
public class ECCServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
   private Signature signature;
   private byte[] signatureBytes;

   ECCServerKeyExchange(PrivateKey privateKey, PublicKey publicKey, RandomCookie randomCookie,
                        RandomCookie randomCookie1, X509Certificate x509Certificate, SecureRandom secureRandom) throws GeneralSecurityException {
      this.signature = Signature.getInstance("SM3withSM2");
      this.signature.initSign(privateKey, secureRandom);
      this.signature.update(randomCookie.random_bytes);
      this.signature.update(randomCookie1.random_bytes);
      byte[] encoded = x509Certificate.getEncoded();
      int length = encoded.length;
      this.signature.update((byte)(length >> 16 & 255));
      this.signature.update((byte)(length >> 8 & 255));
      this.signature.update((byte)(length & 255));
      this.signature.update(encoded);
      this.signatureBytes = this.signature.sign();
   }

   ECCServerKeyExchange(HandshakeInStream handshakeInStream) throws IOException, NoSuchAlgorithmException {
      this.signature = Signature.getInstance("SM3withSM2");
      this.signatureBytes = handshakeInStream.getBytes16();
   }

   boolean verify(PublicKey publicKey, RandomCookie randomCookie, RandomCookie randomCookie1,
                  X509Certificate x509Certificate) throws GeneralSecurityException {
      this.signature.initVerify(publicKey);
      this.signature.update(randomCookie.random_bytes);
      this.signature.update(randomCookie1.random_bytes);
      byte[] encoded = x509Certificate.getEncoded();
      //TODO TODO 不与国标对接，为了配合fabric
      int length = encoded.length;
      this.signature.update((byte)(length >> 16 & 255));
      this.signature.update((byte)(length >> 8 & 255));
      this.signature.update((byte)(length & 255));
      this.signature.update(encoded);
      return this.signature.verify(this.signatureBytes);
   }

   int messageLength() {
      return 2 + this.signatureBytes.length;
   }

   void send(HandshakeOutStream handshakeOutStream) throws IOException {
      handshakeOutStream.putBytes16(this.signatureBytes);
   }

   void print(PrintStream printStream) throws IOException {
      printStream.println("*** ECC ServerKeyExchange");
   }
}
