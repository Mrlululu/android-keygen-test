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
import java.security.Key;
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
    static public final String AES_CBC_NOPADDING = "AES/CBC/PKCS7Padding";

    private byte[] iv;
    private static String DELIMITER = "]";

    public MarshmallowCrypto(Key secretKey) {
        super(secretKey);
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public byte[] encrypt(byte[] clearText) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(CryptoUtils.toBase64(clearText).getBytes());
            this.iv = cipher.getIV();

            String ret = String.format("%s%s%s", CryptoUtils.toBase64(iv), DELIMITER, CryptoUtils.toBase64(cipherText));
            return ret.getBytes();
        }catch (InvalidKeyException e){
            Log.e("Tomek", "key was probably wiped off");
            throw new IllegalArgumentException(e.getMessage(),e);
        }catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e.getMessage(),e);
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

            Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

            byte[] clearText = cipher.doFinal(cipherBytes);

            return CryptoUtils.fromBase64(new String(clearText));
        }catch (InvalidKeyException e){
            Log.e("Tomek", "key was probably wiped off");
            return null;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException  | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
}
