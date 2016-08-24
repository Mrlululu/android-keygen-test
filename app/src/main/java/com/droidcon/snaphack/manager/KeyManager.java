package com.droidcon.snaphack.manager;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyManager {
    private static final String KEY_PREFS = "sdfsdf";
    private final SharedPreferences prefs;
    private static final String PREFS = "prefs";

    public KeyManager(Context context) {
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public void save(String keyName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        prefs.edit().putString(KEY_PREFS, keyName).apply();
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

    }

    public SecretKey read() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        String keyName = prefs.getString(KEY_PREFS, "");
        // key retrieval
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyName, null);
        SecretKey key = entry.getSecretKey();

        return key;
//        byte[] keyBlob = key.getEncoded();
//        return new String(keyBlob, StandardCharsets.UTF_8);
    }

}
