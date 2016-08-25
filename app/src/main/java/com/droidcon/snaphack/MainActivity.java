package com.droidcon.snaphack;

import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.provider.MediaStore;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.widget.Toast;

import com.droidcon.snaphack.fragment.LoginFragment;
import com.droidcon.snaphack.fragment.PhotoListFragment;
import com.droidcon.snaphack.manager.CryptoManager;
import com.droidcon.snaphack.manager.KeyManager;


import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_IMAGE_CAPTURE = 234;
    private static final int REQUEST_IMAGE_CAPTURE_ENCRYPTED = 2344;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getFragmentManager().beginTransaction().add(R.id.content_main, new LoginFragment()).addToBackStack(null).commit();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            Bundle extras = data.getExtras();
            Bitmap imageBitmap = (Bitmap) extras.get("data");

            String fileName = System.currentTimeMillis() + "_photo";

            CryptoManager externalFileManager = null;
            try {
                KeyManager keyManager = new KeyManager(this,false);
                externalFileManager = new CryptoManager(this, ShApplication.getInstance().getConfiguredStorageDirectory(), keyManager.read(),false,keyManager.getKeyAlias());
            } catch (KeyStoreException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                Log.e("Tomek", e.getMessage());
                e.printStackTrace();
            } catch (CertificateException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                Log.e("Tomek", e.getMessage());
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                Log.e("Tomek", e.getMessage());
                e.printStackTrace();
            } catch (IOException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                Log.e("Tomek", e.getMessage());
                e.printStackTrace();
            } catch (UnrecoverableEntryException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                Log.e("Tomek", e.getMessage());
                e.printStackTrace();
            }


            try {
                if (requestCode == REQUEST_IMAGE_CAPTURE) {
                    externalFileManager.savePhoto(imageBitmap, fileName + ".jpg");
                }
                if (requestCode == REQUEST_IMAGE_CAPTURE_ENCRYPTED) {
                    externalFileManager.savePhotoEncrypted(imageBitmap, fileName + "_encrypted.jpg");
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (android.security.KeyChainException e) {
                e.printStackTrace();
            }
        }
    }

    public void loggedIn() {
        getFragmentManager().beginTransaction().add(R.id.content_main, new PhotoListFragment()).addToBackStack(null).commit();
    }

    public void takePhoto() {
        Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (takePictureIntent.resolveActivity(getPackageManager()) != null) {
            startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE);
        }
    }

    public void takePhotoEncrypted() {
        Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (takePictureIntent.resolveActivity(getPackageManager()) != null) {
            startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE_ENCRYPTED);
        }
    }

    @Override
    public void onBackPressed() {
        int  count = getFragmentManager().getBackStackEntryCount();
        if (count > 1) {
            getFragmentManager().popBackStackImmediate();
        }else{
            super.onBackPressed();
        }
    }
}
