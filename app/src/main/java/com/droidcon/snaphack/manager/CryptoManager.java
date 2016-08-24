package com.droidcon.snaphack.manager;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.security.KeyChainException;
import android.util.Log;

import com.droidcon.snaphack.cryptography.Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.SecretKey;

public class CryptoManager {
    private final String path;
    private final Crypto crypto;

    static public final String AES_CBC_NOPADDING = "AES/CBC/PKCS7Padding";
    private String transformation = AES_CBC_NOPADDING;


    public CryptoManager(Context context, String path, SecretKey key) {
        this.path = path;
        this.crypto = Crypto.getInstance(key,transformation);
        checkPathExists();
    }

    private void checkPathExists() {
        File file = new File(path);
        if(!file.exists())
        {
            file.mkdir();
        }
    }

    public void savePhoto(Bitmap imageBitmap, String filename) throws IOException {
        FileOutputStream fileStream = new FileOutputStream(path + filename);
        imageBitmap.compress(Bitmap.CompressFormat.JPEG, 100, fileStream);
        fileStream.close();
    }

    public Bitmap readPhoto(String filename) throws IOException {
        FileInputStream fileStream = new FileInputStream(path + filename);
        Bitmap bitmap = BitmapFactory.decodeStream(fileStream);
        fileStream.close();
        return bitmap;
    }

    public void savePhotoEncrypted(Bitmap imageBitmap, String filename) throws KeyChainException, IOException {
        FileOutputStream fileStream = new FileOutputStream(path + filename);

        ByteArrayOutputStream plainImageBitmapStream = new ByteArrayOutputStream();
        imageBitmap.compress(Bitmap.CompressFormat.JPEG, 100, plainImageBitmapStream);
        byte[] plainBitmapByteArray = plainImageBitmapStream.toByteArray();
        byte[] encryptedBitmapByteArray = crypto.encrypt(plainBitmapByteArray);

        fileStream.write(encryptedBitmapByteArray);

        fileStream.close();
    }

    public Bitmap decryptPhoto(String filename) throws IOException, KeyChainException {

        File encryptedImageFile = new File(path, filename);
        byte[] encryptedBitmapByteArray = new byte[(int) encryptedImageFile.length()];
        InputStream ios = null;
        try {
            ios = new FileInputStream(encryptedImageFile);
            if (ios.read(encryptedBitmapByteArray) == -1) {
                throw new IOException(
                        "EOF reached while trying to read the whole file");
            }
        } finally {
            try {
                if (ios != null)
                    ios.close();
            } catch (IOException e) {
            }
        }
        byte[] decryptedBitmapByteArray;
        try {
            decryptedBitmapByteArray = crypto.decrypt(encryptedBitmapByteArray);
        }catch (IllegalArgumentException e){
            Log.d("Tomek",e.getMessage());
            return null;
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(decryptedBitmapByteArray);
        Bitmap decryptedBitmap = BitmapFactory.decodeStream(inputStream);

        return decryptedBitmap;

    }
}
