package fr.ghizmo.mfapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class SaveSharedPreference
{
    static final String PREF_TOKEN= "";

    static SharedPreferences getSharedPreferences(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx);
    }

    public static void setPrefToken(Context ctx, String userName)
    {
        SharedPreferences.Editor editor = getSharedPreferences(ctx).edit();
        editor.putString(PREF_TOKEN, userName);
        editor.commit();
    }

    public static String getPrefToken(Context ctx)
    {
        return getSharedPreferences(ctx).getString(PREF_TOKEN, "");
    }
}
