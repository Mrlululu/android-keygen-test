package com.droidcon.snaphack.key;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

/**
 * Created by tmaslon on 8/25/2016.
 */
public interface MyKeyStore {

    public void saveKey(String keyAlias) throws KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchAlgorithmException;

    public Key readKey(String keyAlias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException;

    public boolean isHardwareBacked() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;

}
