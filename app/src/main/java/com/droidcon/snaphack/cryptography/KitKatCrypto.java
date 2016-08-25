package com.droidcon.snaphack.cryptography;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.droidcon.snaphack.key.AndroidRsaEngine;
import com.droidcon.snaphack.key.KitKatKeyStore;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.encodings.OAEPEncoding;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by tmaslon on 8/25/2016.
 */
public class KitKatCrypto extends Crypto {

    private static final String INIT_VECT = "RandomInitVector" ;

    private boolean isSigner;
    private String keyAlias;

    private Context context;
    private final SharedPreferences prefs;
    private static final String PREFS = "prefs";

    public KitKatCrypto(Context ctx,Key secretKey,boolean isSigner,String keyAlias) {
        super(secretKey);
        context = ctx;
        this.isSigner = isSigner;
        this.keyAlias = keyAlias;
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }


    @Override
    public byte[] encrypt(byte[] clearText) {
        // First get encrypted symmetric key from store
        String symKeyString = prefs.getString(KitKatKeyStore.SYM_KEY_PREFS, "");
        byte[] encryptedSymKeyBlob = null;
        try {
            encryptedSymKeyBlob = symKeyString.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        byte[] decryptSymKeyBlob = null;
        try {
            decryptSymKeyBlob = decryptWithRsa(encryptedSymKeyBlob);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

        byte[] encryptedText = simpleAesEncrypt(decryptSymKeyBlob,INIT_VECT,clearText);

        return encryptedText;

    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws InvalidCipherTextException {

        // First get encrypted symmetric key from store
        String symKeyString = prefs.getString(KitKatKeyStore.SYM_KEY_PREFS, "");
        byte[] encryptedSymKeyBlob = null;
        try {
            encryptedSymKeyBlob = symKeyString.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        byte[] decryptSymKeyBlob = null;
        try {
            decryptSymKeyBlob = decryptWithRsa(encryptedSymKeyBlob);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

        byte[] decryptedText = simpleAesDecrypt(decryptSymKeyBlob, INIT_VECT, cipherText);

        return decryptedText;
    }

    public byte[] encryptWithRsa(byte[] plainBytes) {
        try {
            AndroidRsaEngine rsa = new AndroidRsaEngine(keyAlias, false);

            Digest digest = new SHA512Digest();
            Digest mgf1digest = new SHA512Digest();
            OAEPEncoding oaep = new OAEPEncoding(rsa, digest, mgf1digest, null);
            oaep.init(true, null);
            byte[] cipherText = oaep.processBlock(plainBytes, 0, plainBytes.length);

            return CryptoUtils.toBase64(cipherText).getBytes();
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decryptWithRsa(byte[] ciphertextRawBytes) throws InvalidCipherTextException {
        try {
            AndroidRsaEngine rsa = new AndroidRsaEngine(keyAlias, false);
            Digest digest = new SHA512Digest();
            Digest mgf1digest = new SHA512Digest();
            OAEPEncoding oaep = new OAEPEncoding(rsa, digest, mgf1digest, null);
            oaep.init(false, null);

            byte[] ciphertextBytes = CryptoUtils.fromBase64(new String(ciphertextRawBytes,"UTF-8"));

            byte[] plain = oaep.processBlock(ciphertextBytes, 0, ciphertextBytes.length);
            return plain;
        }catch (InvalidCipherTextException e){
            throw e;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] simpleAesEncrypt(byte[] key, String initVector, byte[] clearText) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(clearText);
            System.out.println("encrypted string: "
                    + CryptoUtils.toBase64(encrypted));

            return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }


    public static byte[] simpleAesDecrypt(byte[] key, String initVector, byte[] encryptedText) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(encryptedText);

            return original;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }




}



