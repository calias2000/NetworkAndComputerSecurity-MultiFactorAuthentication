package fr.ghizmo.mfapp;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Toast;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.vishnusivadas.advanced_httpurlconnection.PutData;

import java.nio.charset.StandardCharsets;


public class TokenVerificationActivity extends AppCompatActivity {

    private EditText inputCode1, inputCode2, inputCode3, inputCode4, inputCode5, inputCode6, inputCode7, inputCode8, inputCode9, inputCode10;
    private String email;

    public static LazySodiumAndroid lazySodium = new LazySodiumAndroid(new SodiumAndroid());
    private Box.Lazy cryptoBoxLazy = (Box.Lazy) lazySodium;
    private String pubKey;
    private KeyPair clientKeys;
    private KeyPair encryptionKeyPair;
    private byte[] byteNonce;
    private String nonce;
    private String encrypted;
    private Sign.Lazy cryptoSignLazy;
    private KeyPair signKeyPair;
    private String signed;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_token_verification);

        String token = SaveSharedPreference.getPrefToken(TokenVerificationActivity.this);
        email = getIntent().getStringExtra("email");

        Handler handler = new Handler();

        if(token.length() == 0){

            //------ MAKING KEYS

            try {
                clientKeys = cryptoBoxLazy.cryptoBoxKeypair();
                pubKey = clientKeys.getPublicKey().getAsHexString();

                SharedPreferences.Editor editor = getSharedPreferences("PRIVATE_DATA", MODE_PRIVATE).edit();
                editor.putString("PREF_USERPUBKEY", pubKey);
                editor.commit();

            } catch (SodiumException e) {
                e.printStackTrace();
            }

            handler.post(new Runnable(){
                @Override
                public void run() {

                    byteNonce = lazySodium.nonce(Box.NONCEBYTES);
                    nonce = lazySodium.toHexStr(byteNonce);

                    SharedPreferences.Editor editor = getSharedPreferences("PRIVATE_DATA", Context.MODE_PRIVATE).edit();

                    String[] field = new String[3];
                    field[0] = "pubkuser";
                    field[1] = "email";
                    field[2] = "nonce";

                    String[] data = new String[3];
                    data[0] = pubKey;
                    data[1] = email;
                    data[2] = nonce;

                    PutData putData = new PutData(MainActivity.ip+"/keyexchange", "POST", field, data);
                    if (putData.startPut()) {
                        if (putData.onComplete()) {

                            String pubKeyServ = putData.getResult();
                            Key serverPubKey = Key.fromHexString(pubKeyServ);
                            encryptionKeyPair = new KeyPair(serverPubKey, clientKeys.getSecretKey());

                            editor = getSharedPreferences("PRIVATE_DATA", MODE_PRIVATE).edit();
                            editor.putString("PREF_SERVPUBKEY", pubKeyServ);
                            editor.putString("PREF_USERPRIVKEY",clientKeys.getSecretKey().getAsHexString());
                            editor.putString("PREF_USERPUBKEY",clientKeys.getPublicKey().getAsHexString());
                            editor.commit();
                        }
                    }
                }
            });

            //--------------

            inputCode1 = findViewById(R.id.inputCode1);
            inputCode2 = findViewById(R.id.inputCode2);
            inputCode3 = findViewById(R.id.inputCode3);
            inputCode4 = findViewById(R.id.inputCode4);
            inputCode5 = findViewById(R.id.inputCode5);
            inputCode6 = findViewById(R.id.inputCode6);
            inputCode7 = findViewById(R.id.inputCode7);
            inputCode8 = findViewById(R.id.inputCode8);
            inputCode9 = findViewById(R.id.inputCode9);
            inputCode10 = findViewById(R.id.inputCode10);

            setupTokenInputs();

            final ProgressBar progressBar = findViewById(R.id.progressBar);
            final Button buttonVerify = findViewById(R.id.buttonVerify);

            buttonVerify.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (inputCode1.getText().toString().trim().isEmpty()
                            || inputCode2.getText().toString().trim().isEmpty()
                            || inputCode3.getText().toString().trim().isEmpty()
                            || inputCode4.getText().toString().trim().isEmpty()
                            || inputCode5.getText().toString().trim().isEmpty()
                            || inputCode6.getText().toString().trim().isEmpty()
                            || inputCode7.getText().toString().trim().isEmpty()
                            || inputCode8.getText().toString().trim().isEmpty()
                            || inputCode9.getText().toString().trim().isEmpty()
                            || inputCode10.getText().toString().trim().isEmpty()) {
                        Toast.makeText(TokenVerificationActivity.this, "Please enter valid code", Toast.LENGTH_SHORT).show();
                        return;
                    }

                    String code = inputCode1.getText().toString()
                            + inputCode2.getText().toString()
                            + inputCode3.getText().toString()
                            + inputCode4.getText().toString()
                            + inputCode5.getText().toString()
                            + inputCode6.getText().toString()
                            + inputCode7.getText().toString()
                            + inputCode8.getText().toString()
                            + inputCode9.getText().toString()
                            + inputCode10.getText().toString();

                    progressBar.setVisibility(View.VISIBLE);
                    buttonVerify.setVisibility(View.INVISIBLE);

                    //------ SIGNING CREATETOKEN
                    cryptoSignLazy = (Sign.Lazy) lazySodium;

                    try {
                        signKeyPair = cryptoSignLazy.cryptoSignKeypair();
                    } catch (SodiumException e) {
                        e.printStackTrace();
                    }

                    try {
                        signed = cryptoSignLazy.cryptoSign(code, signKeyPair.getSecretKey().getAsHexString());
                    } catch (SodiumException e) {
                        e.printStackTrace();
                    }

                    //------ ENCRYPT SIGN(CREATETOKEN)
                    try {
                        encrypted = cryptoBoxLazy.cryptoBoxEasy(signed, byteNonce, encryptionKeyPair);
                    } catch (SodiumException e) {
                        e.printStackTrace();
                    }

                    handler.post(new Runnable() {
                            @Override
                            public void run() {

                                String[] field = new String[4];
                                field[0] = "email";
                                field[1] = "createToken";
                                field[2] = "signedPubKey";
                                field[3] = "nonce";

                                String[] data = new String[4];
                                data[0] = email;
                                data[1] = encrypted;
                                data[2] = signKeyPair.getPublicKey().getAsHexString();
                                data[3] = nonce;

                                PutData putData = new PutData(MainActivity.ip+"/atestation", "POST", field, data);
                                if (putData.startPut()) {
                                    if (putData.onComplete()) {
                                        progressBar.setVisibility(View.GONE);
                                        String result = putData.getResult();

                                        if (result.contains("create token valid")) {

                                            SaveSharedPreference.setPrefToken(TokenVerificationActivity.this, code);

                                            Intent intent = new Intent(getApplicationContext(), TokenDisplayActivity.class);
                                            intent.putExtra("email",email);
                                            startActivity(intent);
                                            finish();

                                        } else {

                                            //bad token
                                            Toast.makeText(TokenVerificationActivity.this, "Wrong Token !", Toast.LENGTH_SHORT).show();
                                            buttonVerify.setVisibility(View.VISIBLE);
                                            inputCode1.setText("");
                                            inputCode2.setText("");
                                            inputCode3.setText("");
                                            inputCode4.setText("");
                                            inputCode5.setText("");
                                            inputCode6.setText("");
                                            inputCode7.setText("");
                                            inputCode8.setText("");
                                            inputCode9.setText("");
                                            inputCode10.setText("");
                                            inputCode1.requestFocus();

                                        }
                                    }
                                }
                            }
                        });
                }
            });

        } else if (token.length() != 0){

            SharedPreferences preferences = getSharedPreferences("PRIVATE_DATA", Context.MODE_PRIVATE);

            byteNonce = lazySodium.nonce(Box.NONCEBYTES);
            nonce = lazySodium.toHexStr(byteNonce);

            String pubKeyServ = preferences.getString("PREF_SERVPUBKEY", "");
            Key serverPubKey = Key.fromHexString(pubKeyServ);

            String privKeyUser = preferences.getString("PREF_USERPRIVKEY", "");
            Key userSecretKey = Key.fromHexString(privKeyUser);

            //------ SIGNING CREATETOKEN
            cryptoSignLazy = (Sign.Lazy) lazySodium;

            try {
                signKeyPair = cryptoSignLazy.cryptoSignKeypair();
            } catch (SodiumException e) {
                e.printStackTrace();
            }

            try {
                signed = cryptoSignLazy.cryptoSign(token, signKeyPair.getSecretKey().getAsHexString());
            } catch (SodiumException e) {
                e.printStackTrace();
            }

            encryptionKeyPair = new KeyPair(serverPubKey, userSecretKey);

            //encrypt token
            try {
                encrypted = cryptoBoxLazy.cryptoBoxEasy(signed, byteNonce, encryptionKeyPair);
            } catch (SodiumException e) {
                e.printStackTrace();
            }

            handler.post(new Runnable() {
                @Override
                public void run() {

                    String[] field = new String[4];
                    field[0] = "email";
                    field[1] = "createToken";
                    field[2] = "signedPubKey";
                    field[3] = "nonce";

                    String[] data = new String[4];
                    data[0] = email;
                    data[1] = encrypted;
                    data[2] = signKeyPair.getPublicKey().getAsHexString();
                    data[3] = nonce;

                    PutData putData = new PutData(MainActivity.ip+"/atestation", "POST", field, data);
                    if (putData.startPut()) {
                        if (putData.onComplete()) {

                            String result = putData.getResult();

                            if (result.contains("create token valid")) {

                                Intent intent = new Intent(getApplicationContext(), TokenDisplayActivity.class);
                                intent.putExtra("email",email);
                                startActivity(intent);
                                finish();

                            } else {

                                //bad token

                            }
                        }
                    }
                }
            });
        };
    }

    private void setupTokenInputs(){
        inputCode1.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode2.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode2.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode3.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode3.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode4.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode4.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode5.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode5.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode6.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode6.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode7.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode7.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode8.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode8.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode9.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        inputCode9.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {

                if(!s.toString().trim().isEmpty()){
                    inputCode10.requestFocus();
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
    }
}