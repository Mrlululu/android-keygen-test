package com.droidcon.snaphack.cryptography;

import android.os.Build;

import java.security.Key;

import javax.crypto.SecretKey;

/**
 * Created by tomasz on 24.08.2016.
 */
public abstract class Crypto {

    private static final boolean IS_M = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    private static final boolean IS_KK = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;

    protected Key secretKey;

    protected Crypto(Key secretKey) {
        this.secretKey = secretKey;
    }

    public static Crypto getInstance(Key secretKey, String transformation) {
        if (IS_M) {
            return new MarshmallowCrypto(secretKey, transformation);
        }else if(IS_KK){
            return new KitKatCrypto(secretKey, transformation);
        }else{
            return new KitKatCrypto(secretKey,transformation);
        }
    }

    public abstract byte[] encrypt(byte[] clearText);

    public abstract byte[] decrypt(final byte[] cipherText);


}
