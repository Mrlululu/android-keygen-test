package com.droidcon.snaphack.key;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.KeyChain;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by tmaslon on 8/25/2016.
 */
public class MarshmallowKeyStore implements MyKeyStore {

    private String keyAlias = null;

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void saveKey(String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        this.keyAlias = keyAlias;

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        if(ks.containsAlias(keyAlias)){
            Log.d("Tomek", "Key with name: " + keyAlias + " already exists");
            return;
        }

        // key generation
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias,
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

    @Override
    public SecretKey readKey(String keyAlias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {

        // key retrieval
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyAlias, null);
        SecretKey key = entry.getSecretKey();

        return key;
    }

    @Override
    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        if(keyAlias!=null){
            // key retrieval
//            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
//            ks.load(null);
//
//            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyAlias, null);
//            SecretKey key = entry.getSecretKey();
    //
    //        KeyFactory keyFactory;
    //        try {

                  // TODO: For some reasons keystore returns exception that AES algorithm is not supported even though we generated it previously
    //            keyFactory =  KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
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
        }

        return KeyChain.isBoundKeyAlgorithm(KeyProperties.KEY_ALGORITHM_RSA);
    }
}
