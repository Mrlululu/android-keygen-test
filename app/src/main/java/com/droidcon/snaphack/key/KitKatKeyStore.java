package com.droidcon.snaphack.key;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

/**
 * Created by tmaslon on 8/25/2016.
 */
public class KitKatKeyStore implements MyKeyStore {

    boolean isSigner = false;

    public KitKatKeyStore(boolean isSigner) {
        this.isSigner = isSigner;
    }

    @Override
    public void saveKey(String keyAlias) {

    }

    @Override
    public Key readKey(String keyAlias) {
        return null;
    }

    @Override
    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        return false;
    }
}
