package fr.ghizmo.mfapp;

import org.junit.Test;

import static org.junit.Assert.*;

import android.view.View;

import com.vishnusivadas.advanced_httpurlconnection.PutData;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class AppTests {

    @Test
    public void correctLogin() {

        String[] field = new String[2];
        field[0] = "email";
        field[1] = "password";

        String[] data = new String[2];
        data[0] = "demouser@x.x";
        data[1] = "Demouser2022!";

        PutData putData = new PutData(MainActivity.ip+"/appLogin", "POST", field, data);
        if (putData.startPut()) {
            if (putData.onComplete()) {
                String result = putData.getResult();
                assertEquals("Credentials Accepted", result);
            }
        }
    }

    @Test
    public void emailNotExistLogin() {

        String[] field = new String[2];
        field[0] = "email";
        field[1] = "password";

        String[] data = new String[2];
        data[0] = "demo@v.v";
        data[1] = "Demouser2022!";

        PutData putData = new PutData(MainActivity.ip+"/appLogin", "POST", field, data);
        if (putData.startPut()) {
            if (putData.onComplete()) {
                String result = putData.getResult();
                assertEquals("Email does not exist", result);
            }
        }
    }

    @Test
    public void incorrectPwLogin() {

        String[] field = new String[2];
        field[0] = "email";
        field[1] = "password";

        String[] data = new String[2];
        data[0] = "demouser@x.x";
        data[1] = "Demouser";

        PutData putData = new PutData(MainActivity.ip+"/appLogin", "POST", field, data);
        if (putData.startPut()) {
            if (putData.onComplete()) {
                String result = putData.getResult();
                assertEquals("Incorrect Credentials", result);
            }
        }
    }
}