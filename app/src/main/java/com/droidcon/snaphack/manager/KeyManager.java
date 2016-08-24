package com.droidcon.snaphack.manager;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyChain;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyManager {
    private static final String KEY_PREFS = "sdfsdf";
    private final SharedPreferences prefs;
    private static final String PREFS = "prefs";

    public KeyManager(Context context) {
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public void save(String keyName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        prefs.edit().putString(KEY_PREFS, keyName).apply();

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        if(ks.containsAlias(keyName)){
            Log.d("Tomek", "Key with name: " + keyName + " already exists");
            return;
        }

        // key generation
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        KeyGenParameterSpec keySpec = builder
                .setKeySize(256)
                .setBlockModes("CBC")
                .setEncryptionPaddings("PKCS7Padding")
//                .setRandomizedEncryptionRequired(true)
//                .setUserAuthenticationRequired(true)
//                .setUserAuthenticationValidityDurationSeconds(5 * 60)
                .build();

        KeyGenerator kg = KeyGenerator.getInstance("AES", "AndroidKeyStore");
        kg.init(keySpec);
        SecretKey generatedKey = kg.generateKey();

        KeyFactory keyFactory;
        try {
            keyFactory =
                    KeyFactory.getInstance(generatedKey.getAlgorithm(), "AndroidKeyStore");

            KeyInfo keyInfo = keyFactory.getKeySpec(generatedKey, KeyInfo.class);
            if (keyInfo.isInsideSecureHardware()) {
                boolean result = true;
            }

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public SecretKey read() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        String keyName = prefs.getString(KEY_PREFS, "");
        // key retrieval
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyName, null);
        SecretKey key = entry.getSecretKey();

        return key;
    }


    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException, InvalidKeySpecException {
        String keyName = prefs.getString(KEY_PREFS, "");
        // key retrieval
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyName, null);
        SecretKey key = entry.getSecretKey();
//
//        KeyFactory keyFactory;
//        try {
//            keyFactory =
//                    KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
//
//        }catch (Exception e){
//            throw e;
//        }
//
//        KeyInfo keyInfo = keyFactory.getKeySpec(key, KeyInfo.class);
//        if (keyInfo.isInsideSecureHardware()) {
//            return true;
//        }
//
//        return false;

        return KeyChain.isBoundKeyAlgorithm(KeyProperties.KEY_ALGORITHM_RSA);

    }

}
