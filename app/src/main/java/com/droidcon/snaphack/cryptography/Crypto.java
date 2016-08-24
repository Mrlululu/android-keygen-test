package com.droidcon.snaphack.cryptography;

import android.os.Build;

import javax.crypto.SecretKey;

/**
 * Created by tomasz on 24.08.2016.
 */
public abstract class Crypto {

    protected SecretKey secretKey;

    protected Crypto(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public static Crypto getInstance(SecretKey secretKey, String transformation) {
        //if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return new MarshmallowCrypto(secretKey, transformation);
        //}
    }

    public abstract byte[] encrypt(byte[] clearText);

    public abstract byte[] decrypt(final byte[] cipherText);


}
