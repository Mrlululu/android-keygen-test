package com.droidcon.snaphack.manager;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyChain;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.droidcon.snaphack.key.KitKatKeyStore;
import com.droidcon.snaphack.key.MarshmallowKeyStore;
import com.droidcon.snaphack.key.MyKeyStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
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

    private static final boolean IS_M = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    private static final boolean IS_KK = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;

    private static final String KEY_PREFS = "sdfsdf";
    private final SharedPreferences prefs;
    private static final String PREFS = "prefs";
    MyKeyStore myKeyStore = null;

    public KeyManager(Context context) {
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);

        if(IS_M){
            myKeyStore = new MarshmallowKeyStore();
        }else if(IS_KK){
            myKeyStore = new KitKatKeyStore();
        } else {
            myKeyStore = new KitKatKeyStore();
        }

    }

    public void save(String keyName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        prefs.edit().putString(KEY_PREFS, keyName).apply();
        myKeyStore.saveKey(keyName);
    }

    public Key read() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        String keyName = prefs.getString(KEY_PREFS, "");
        Key key = myKeyStore.readKey(keyName);
        return key;
    }


    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException, InvalidKeySpecException {
        return myKeyStore.isHardwareBacked();
    }

}
