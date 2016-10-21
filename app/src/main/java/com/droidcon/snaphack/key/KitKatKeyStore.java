package com.droidcon.snaphack.key;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyChain;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.droidcon.snaphack.cryptography.Crypto;
import com.droidcon.snaphack.cryptography.KitKatCrypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Created by tmaslon on 8/25/2016.
 */
public class KitKatKeyStore implements MyKeyStore {

    public static final String SYM_KEY_PREFS = "qwerty";
    private static final int KEY_LENGTH = 128;
    private final SharedPreferences prefs;
    private static final String PREFS = "prefs";

    public static final String RSA_KEY_PREFIX = "rsa_key_";
    public static final String AES_KEY_PREFIX = "aes_key_";

    Context context;

    public KitKatKeyStore(Context ctx) {
        context = ctx;

        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    @SuppressLint("NewApi")
    @Override
    public void saveKey(String keyAlias) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {

        String rsaKeyAlias = RSA_KEY_PREFIX + keyAlias;
        String aesKeyAlias = AES_KEY_PREFIX + keyAlias;

        // Check if key exist
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        if(!ks.containsAlias(rsaKeyAlias)) {
            Log.d("Tomek", "Key with name: " + rsaKeyAlias + " does not exist");

            // Generate rsa key pair in SE
            Calendar notBefore = Calendar.getInstance();
            Calendar notAfter = Calendar.getInstance();
            notAfter.add(1, Calendar.YEAR);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(rsaKeyAlias)
                    .setSubject(
                            new X500Principal(String.format("CN=%s, OU=%s", rsaKeyAlias,
                                    context.getPackageName())))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(notBefore.getTime())
                    .setEndDate(notAfter.getTime()).build();
            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA",
                    "AndroidKeyStore");
            kpGenerator.initialize(spec);
            KeyPair kp = kpGenerator.generateKeyPair();

            // generate symetric key that will be encoded with TEE rsa key
            SecretKey symKey = generateAesKey();

            KitKatCrypto crypto = (KitKatCrypto)Crypto.getInstance(context,null,keyAlias);
            byte[] encryptedKey  = crypto.encryptWithRsa(symKey.getEncoded());
            String encryptedKeyString = null;
            try {
                encryptedKeyString = new String(encryptedKey,"UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }

            // place encrypted symetric key in store
            prefs.edit().putString(aesKeyAlias, encryptedKeyString).apply();
        }


    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    @Override
    public Key readKey(String keyAlias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {

        String rsaKeyAlias = RSA_KEY_PREFIX + keyAlias;
        Key outputKey = null;

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        java.security.KeyStore.Entry keyEntry = keyStore.getEntry(
                rsaKeyAlias, null);
        RSAPublicKey publicKey = (RSAPublicKey) ((java.security.KeyStore.PrivateKeyEntry) keyEntry)
                .getCertificate().getPublicKey();
        PrivateKey privateKey =  ((KeyStore.PrivateKeyEntry) keyEntry)
                .getPrivateKey();


        outputKey = privateKey;

        return outputKey;
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    @Override
    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        return KeyChain.isBoundKeyAlgorithm(KeyProperties.KEY_ALGORITHM_RSA);
    }


    private static SecretKey generateAesKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(KEY_LENGTH);
            SecretKey key = kg.generateKey();

            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
