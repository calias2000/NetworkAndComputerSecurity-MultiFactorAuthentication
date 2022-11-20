package fr.ghizmo.mfapp;

import static fr.ghizmo.mfapp.TokenVerificationActivity.lazySodium;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.widget.EditText;
import android.widget.TextView;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.vishnusivadas.advanced_httpurlconnection.PutData;

import java.util.Arrays;

public class TokenDisplayActivity extends AppCompatActivity {

    private String email;
    private Sign.Lazy cryptoSignLazy;
    private KeyPair signKeyPair;
    private String signed;
    private KeyPair encryptionKeyPair;
    private String encrypted;
    private Box.Lazy cryptoBoxLazy = (Box.Lazy) lazySodium;
    private byte[] byteNonce;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_token_display);

        String token = SaveSharedPreference.getPrefToken(TokenDisplayActivity.this);
        email = getIntent().getStringExtra("email");

        TextView loginToken = (TextView)findViewById(R.id.loginToken);

        int delay = 5000;

        SharedPreferences preferences = getSharedPreferences("PRIVATE_DATA", Context.MODE_PRIVATE);
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
        //------

        encryptionKeyPair = new KeyPair(serverPubKey, userSecretKey);
        byteNonce = lazySodium.nonce(Box.NONCEBYTES);
        String nonceSend = lazySodium.toHexStr(byteNonce);

        //encrypt token
        try {
            encrypted = cryptoBoxLazy.cryptoBoxEasy(signed, byteNonce, encryptionKeyPair);
        } catch (SodiumException e) {
            e.printStackTrace();
        }



        Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                String[] field = new String[4];
                field[0] = "email";
                field[1] = "createToken";
                field[2] = "nonce";
                field[3] = "signedPubKey";

                String[] data = new String[4];
                data[0] = email;
                data[1] = encrypted;
                data[2] = nonceSend;
                data[3] = signKeyPair.getPublicKey().getAsHexString();

                PutData putData = new PutData(MainActivity.ip+"/loginToken", "POST", field, data);
                if (putData.startPut()) {
                    if (putData.onComplete()) {


                        String result = putData.getResult();

                        String[] arrOfStr = result.split(":", 0);
                        byte[] nonce = lazySodium.toBinary(arrOfStr[0]);
                        byte[] message = lazySodium.toBinary(arrOfStr[1]);
                        String loginTokenEncrypted = lazySodium.toHexStr(Arrays.copyOfRange(message, 24, message.length));
                        Key signKey = Key.fromHexString(arrOfStr[2]);

                        String decryptedMessage = "";

                        try {
                            decryptedMessage = cryptoBoxLazy.cryptoBoxOpenEasy(loginTokenEncrypted, nonce, encryptionKeyPair);
                            System.out.println(decryptedMessage);
                        } catch (SodiumException e) {
                            e.printStackTrace();
                        }

                        String resultingMessage = cryptoSignLazy.cryptoSignOpen(decryptedMessage, signKey);

                        loginToken.setText(resultingMessage);

                    }
                }

                handler.postDelayed(this, delay);

            }
        }, delay);
    }
}