package com.droidcon.snaphack.cryptography;

/**
 * Created by tomasz on 24.08.2016.
 */

import android.util.Base64;

public class CryptoUtils {

    private CryptoUtils() {
    }

    public static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.decode(base64, Base64.NO_WRAP);
    }

}
