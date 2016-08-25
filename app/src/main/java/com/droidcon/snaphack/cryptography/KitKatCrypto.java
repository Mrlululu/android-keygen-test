package com.droidcon.snaphack.cryptography;

import com.droidcon.snaphack.key.AndroidRsaEngine;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

/**
 * Created by tmaslon on 8/25/2016.
 */
public class KitKatCrypto extends Crypto {

    private boolean isSigner;

    public KitKatCrypto(Key secretKey, String transformation) {
        super(secretKey);
        if(transformation.equals("signer")){
            isSigner = true;
        }else{
            isSigner = false;
        }
    }

    @Override
    public byte[] encrypt(byte[] clearText) {
        AndroidRsaEngine rsa = new AndroidRsaEngine(secretKey, false);





        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] cipherText) {
        return new byte[0];
    }


}



