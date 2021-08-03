package org.whu.gmssl.jsse.utils;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

//TODO modify by ringo
public class SM2KeyExchangeUtil {
    public SM2KeyExchangeUtil() {
    }

    public static BigInteger generateRandom(ECPublicKey var0, SecureRandom var1) {
        BigInteger var2 = var0.getParameters().getN();
        return generateRandom(var2, var1);
    }

    public static BigInteger generateRandom(BigInteger var0, SecureRandom var1) {
        BigInteger var2 = gen(var0, var1);
        return var2;
    }

    public static BigInteger gen(BigInteger var0, Random var1) {
        BigInteger var2 = null;
        int var3 = var0.bitLength();
        int var4 = var3 / 8;
        byte var5 = 64;
        int var6 = 0;

        while(true) {
            do {
                var2 = new BigInteger(var3, var1);
            } while(var2.equals(BigInteger.ZERO));

            if (var2.compareTo(var0) < 0) {
                int var7 = var2.bitLength() / 8;
                if (var7 == var4) {
                    ++var6;
                    if (var6 > var5) {
                        return var2;
                    }
                }
            }
        }
    }
}
