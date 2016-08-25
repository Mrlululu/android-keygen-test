package com.droidcon.snaphack.service;

import android.content.Context;
import android.support.design.widget.Snackbar;
import android.util.Log;

import com.droidcon.snaphack.manager.KeyManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import retrofit.Callback;
import retrofit.RestAdapter;
import retrofit.RetrofitError;
import retrofit.client.Response;

public class ServiceManager {
    private static final String TAG = "Service";
    private LoginService restService;
    private Context context;

    public ServiceManager(Context context) {
        this.context = context;
        RestAdapter restAdapter = new RestAdapter.Builder()
                .setEndpoint("http://52.32.159.250")
                .build();
        restService = restAdapter.create(LoginService.class);
    }

//    public void login(String username, String password, final Callback<LoginResponse> callback) {
//        restService.login(new LoginRequest(username, password), new Callback<LoginResponse>() {
//            @Override
//            public void success(LoginResponse loginResponse, Response response) {
//                try{
//                    new KeyManager(context,false).save(loginResponse.getKey());
//                    callback.success(loginResponse, response);
//                } catch (NoSuchProviderException e) {
//                    e.printStackTrace();
//                } catch (NoSuchAlgorithmException e) {
//                    e.printStackTrace();
//                } catch (InvalidAlgorithmParameterException e) {
//                    e.printStackTrace();
//                } catch (KeyStoreException e) {
//                    e.printStackTrace();
//                }
//            }
//
//            @Override
//            public void failure(RetrofitError error) {
//                Log.e(TAG, error.getLocalizedMessage());
//                callback.failure(error);
//            }
//        });
//    }
}