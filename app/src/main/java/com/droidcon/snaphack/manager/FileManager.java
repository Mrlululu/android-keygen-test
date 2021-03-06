package com.droidcon.snaphack.manager;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.support.annotation.NonNull;

import com.droidcon.snaphack.ShApplication;
import com.droidcon.snaphack.model.PhotoItem;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class FileManager {
    private final Context context;

    public FileManager(Context context) {
        this.context = context;
    }

    public void deleteAll() {
        File dir = new File(ShApplication.getInstance().getConfiguredStorageDirectory());
        String[] files = dir.list();

        for (String file : files) {
            File deleteFile = new File(ShApplication.getInstance().getConfiguredStorageDirectory() + file);
            deleteFile.delete();
        }
    }

    public List<PhotoItem> getAll() {
        final List<PhotoItem> photos = new ArrayList<>();

        File dir = new File(ShApplication.getInstance().getConfiguredStorageDirectory());
        String[] files = dir.list();
        if (files == null) {
            return photos;
        }

        CryptoManager manager = null;
        try {
            KeyManager keyManager = new KeyManager(context);
            manager = new CryptoManager(context, ShApplication.getInstance().getConfiguredStorageDirectory(), keyManager.read(),keyManager.getKeyAlias());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        for (String file : files) {
            PhotoItem photo = null;
            photo = tryToGetAdecryptedPhoto(manager, file);
            if (photo == null) {
                photo = tryToGetANormalPhoto(manager, file);
            }
            if (photo != null) {
                photos.add(photo);
            }
        }
        return photos;
    }

    public boolean isKeyStoreHardwareBacked(){
        try {
            return new KeyManager(context).isHardwareBacked();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return false;
    }


    private PhotoItem tryToGetANormalPhoto(CryptoManager manager, String file) {
        try {
            Bitmap bitmap = manager.readPhoto(file);
            if (bitmap == null) {
                return null;
            }
            Bitmap bitmapMarked = mark(bitmap, "public", Color.GREEN);
            return new PhotoItem(bitmapMarked, file);
        } catch (IOException e) {
        }
        return null;
    }

    @NonNull
    private PhotoItem tryToGetAdecryptedPhoto(CryptoManager manager, String file) {
        try {
            Bitmap decryptedFile = manager.decryptPhoto(file);
            if (decryptedFile == null) {
                return null;
            }
            Bitmap decryptedFileMarked = mark(decryptedFile, "private", Color.RED);
            return new PhotoItem(decryptedFileMarked, file);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (android.security.KeyChainException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Bitmap mark(Bitmap src, String watermark, int color) {
        int w = src.getWidth();
        int h = src.getHeight();
        Bitmap result = Bitmap.createBitmap(w, h, src.getConfig());

        Canvas canvas = new Canvas(result);
        canvas.drawBitmap(src, 0, 0, null);

        Paint paint = new Paint();
        paint.setColor(color);
        paint.setTextSize(18.0f);
        paint.setAntiAlias(true);
        canvas.rotate(-45);
        canvas.drawText(watermark, src.getWidth() / 8, src.getHeight(), paint);

        return result;
    }

}
