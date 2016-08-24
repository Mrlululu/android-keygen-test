package com.droidcon.snaphack.cryptography;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by tomasz on 24.08.2016.
 */
public class MarshmallowCrypto extends Crypto {
    private final String  transformation;

    private byte[] iv;
    private static String DELIMITER = "]";

    public MarshmallowCrypto(SecretKey secretKey, String transformation) {
        super(secretKey);
        this.transformation = transformation;
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public byte[] encrypt(byte[] clearText) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(CryptoUtils.toBase64(clearText).getBytes());
            this.iv = cipher.getIV();

            String ret = String.format("%s%s%s", CryptoUtils.toBase64(iv), DELIMITER, CryptoUtils.toBase64(cipherText));
            return ret.getBytes();
        }  catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("There was an error encrypting Shelf storage: " + e.getMessage(), e);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public byte[] decrypt(byte[] cipherText) {
        if (cipherText == null) {
            return null;
        }

        try {
            String cipherString = new String(cipherText);
            String[] fields = cipherString.split(DELIMITER);

            byte[] iv = CryptoUtils.fromBase64(fields[0]);
            byte[] cipherBytes = CryptoUtils.fromBase64(fields[1]);

            Cipher cipher = Cipher.getInstance(transformation);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

            byte[] clearText = cipher.doFinal(cipherBytes);

            return CryptoUtils.fromBase64(new String(clearText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("There was an error decrypting Shelf storage: " + e.getMessage(), e);
        }
    }
}
