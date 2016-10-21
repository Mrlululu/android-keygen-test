package com.droidcon.snaphack.cryptography;

import android.content.Context;
import android.os.Build;


import org.spongycastle.crypto.InvalidCipherTextException;

import java.security.Key;

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

    public static Crypto getInstance(Context ctx,Key secretKey,String keyAlias) {
        if (IS_M) {
            return new KitKatCrypto(ctx,secretKey,keyAlias);//new MarshmallowCrypto(secretKey);
        }else if(IS_KK){
            return new KitKatCrypto(ctx,secretKey,keyAlias);
        }else{
            return new KitKatCrypto(ctx,secretKey,keyAlias);
        }
    }

    public abstract byte[] encrypt(byte[] clearText);

    public abstract byte[] decrypt(final byte[] cipherText) throws InvalidCipherTextException;


}
