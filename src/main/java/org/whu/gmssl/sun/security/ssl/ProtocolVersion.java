/*
 * Copyright (c) 2002, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.whu.gmssl.sun.security.ssl;

/**
 * Type safe enum for an SSL/TLS protocol version. Instances are obtained
 * using the static factory methods or by referencing the static members
 * in this class. Member variables are final and can be accessed without
 * accessor methods.
 *
 * There is only ever one instance per supported protocol version, this
 * means == can be used for comparision instead of equals() if desired.
 *
 * Checks for a particular version number should generally take this form:
 *
 * if (protocolVersion.v >= ProtocolVersion.TLS10) {
 *   // TLS 1.0 code goes here
 * } else {
 *   // SSL 3.0 code here
 * }
 *
 * @author  Andreas Sterbenz
 * @since   1.4.1
 */
public final class ProtocolVersion implements Comparable<ProtocolVersion> {

    // The limit of maximum protocol version
    final static int LIMIT_MAX_VALUE = 0xFFFF;

    // The limit of minimum protocol version
    final static int LIMIT_MIN_VALUE = 0x0000;

    // Dummy protocol version value for invalid SSLSession
    final static ProtocolVersion NONE = new ProtocolVersion(-1, "NONE");

    // If enabled, send/ accept SSLv2 hello messages
    final static ProtocolVersion SSL20Hello = new ProtocolVersion(0x0002,
                                                                "SSLv2Hello");

    // SSL 3.0
    final static ProtocolVersion SSL30 = new ProtocolVersion(0x0300, "SSLv3");

    // TLS 1.0
    final static ProtocolVersion TLS10 = new ProtocolVersion(0x0301, "TLSv1");

    // TLS 1.1
    final static ProtocolVersion TLS11 = new ProtocolVersion(0x0302, "TLSv1.1");

    // TLS 1.2
    final static ProtocolVersion TLS12 = new ProtocolVersion(0x0303, "TLSv1.2");

    // TODO modify by ringo

    // GMTLS 1.0
    final static ProtocolVersion GMSSL10 = new ProtocolVersion(1, 0, "GMSSLv1.0");

    //TODO GMTLS 1.1 ??????fabric???minor??????
    final static ProtocolVersion GMSSL11 = new ProtocolVersion(1, 2, "GMSSLv1.1");

    private static final boolean FIPS = GMJsse.isFIPS();

    // minimum version we implement (SSL 3.0)
    final static ProtocolVersion MIN = FIPS ? TLS10 : SSL30;

    // maximum version we implement (TLS 1.2)
    final static ProtocolVersion MAX = TLS12;

    // ProtocolVersion to use by default (TLS 1.2)
    final static ProtocolVersion DEFAULT = TLS12;

    // Default version for hello messages (SSLv2Hello)
    final static ProtocolVersion DEFAULT_HELLO = FIPS ? TLS10 : SSL30;

    // version in 16 bit MSB format as it appears in records and
    // messages, i.e. 0x0301 for TLS 1.0
    public final int v;

    // major and minor version
    public final byte major, minor;

    // name used in JSSE (e.g. TLSv1 for TLS 1.0)
    final String name;

    private boolean isgm = false;

    // private
    private ProtocolVersion(int v, String name) {
        this.v = v;
        this.name = name;
        major = (byte)(v >>> 8);
        minor = (byte)(v & 0xff);
    }

    //TODO modify by ringo
    private ProtocolVersion(int major, int minor, String name) {
        this.v = TLS11.v;
        //TODO ????????????netty?????????tls??????????????????????????????
        this.major = 3;
//        this.major = (byte)major;
        this.minor = (byte)minor;
        this.name = name;
        this.isgm = true;
    }


    public boolean isIsgm() {
        return isgm;
    }

    // private
    private static ProtocolVersion valueOf(int v) {
        if (v == SSL30.v) {
            return SSL30;
        } else if (v == TLS10.v) {
            return TLS10;
        } else if (v == TLS11.v) {
            return TLS11;
        } else if (v == TLS12.v) {
            return TLS12;
        } else if (v == SSL20Hello.v) {
            return SSL20Hello;
        } else {
            int major = (v >>> 8) & 0xff;
            int minor = v & 0xff;
            return new ProtocolVersion(v, "Unknown-" + major + "." + minor);
        }
    }

    /**
     * Return a ProtocolVersion with the specified major and minor version
     * numbers. Never throws exceptions.
     */
    public static ProtocolVersion valueOf(int major, int minor) {
        //TODO modify by ringo
        if (major == 3) {
            if (minor == 0) {
                return GMSSL10;
            }

            if (minor == 2) {
                return GMSSL11;
            }
        }
        major &= 0xff;
        minor &= 0xff;
        int v = (major << 8) | minor;
        return valueOf(v);
    }

    /**
     * Return a ProtocolVersion for the given name.
     *
     * @exception IllegalArgumentException if name is null or does not
     * identify a supported protocol
     */
    static ProtocolVersion valueOf(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Protocol cannot be null");
        }

        if (FIPS && (name.equals(SSL30.name) || name.equals(SSL20Hello.name))) {
            throw new IllegalArgumentException
                ("Only TLS 1.0 or later allowed in FIPS mode");
        }

        if (name.equals(SSL30.name)) {
            return SSL30;
        } else if (name.equals(TLS10.name)) {
            return TLS10;
        } else if (name.equals(TLS11.name)) {
            return TLS11;
        } else if (name.equals(TLS12.name)) {
            return TLS12;
        } else if (name.equals(SSL20Hello.name)) {
            return SSL20Hello;
        //TODO modify by ringo
        } else if (name.equals(GMSSL10.name)) {
            return GMSSL10;
        } else if (name.equals(GMSSL11.name)) {
            return GMSSL11;
        } else {
            throw new IllegalArgumentException(name);
        }
    }

    @Override
    public String toString() {
        return name;
    }

    /**
     * Compares this object with the specified object for order.
     */
    @Override
    public int compareTo(ProtocolVersion protocolVersion) {
        return this.v - protocolVersion.v;
    }
}
