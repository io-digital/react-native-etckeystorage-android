package za.co.io.etckeystorage;

import android.security.KeyPairGeneratorSpec;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

import za.co.io.ethereumj_android.crypto.ECKey;

public final class ETCKeyStorageModule extends ReactContextBaseJavaModule {

    public ETCKeyStorageModule(final ReactApplicationContext rctx) {
        super(rctx);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @Override
    public final String getName() {
        return "ETCKeyStorage";
    }

    private WritableMap newKeyPair() throws IOException,
            KeyStoreException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            UnrecoverableEntryException {
        WritableMap wm = Arguments.createMap();
        ECKey eck = new ECKey(Security.getProvider("SC"), new SecureRandom());
        wm.putString("private", Hex.toHexString(eck.getPrivKeyBytes()));
        wm.putString("public", Hex.toHexString(eck.getPubKey()));
        wm.putString("account", "0x" + Hex.toHexString(ECKey.computeAddress(eck.getPubKey())));
        return wm;
    }

    private WritableMap randomBytes() {
        WritableMap wm = Arguments.createMap();
        SecureRandom sr = new SecureRandom();
        byte[] did = new byte[32];
        sr.nextBytes(did);
        wm.putString("random", Hex.toHexString(did));
        return wm;
    }

    @ReactMethod
    @SuppressWarnings("unused")
    public void getRandomBytesPromise(Promise promise) {
        promise.resolve(this.randomBytes());
    }

    @ReactMethod
    @SuppressWarnings("unused")
    public void requestNewKeyPairPromise(Promise promise) {
        try {
            promise.resolve(this.newKeyPair());
        } catch (
            IllegalArgumentException |
            NoSuchProviderException |
            IOException |
            KeyStoreException |
            NoSuchAlgorithmException |
            CertificateException |
            UnrecoverableEntryException e
        ) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @SuppressWarnings("unused")
    public void getKeyAliasesPromise(Promise promise) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            WritableMap wm = Arguments.createMap();
            WritableArray wa = Arguments.createArray();
            wm.putArray("aliases", wa);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) wa.pushString(aliases.nextElement());
            promise.resolve(wm);
        } catch (
            KeyStoreException |
            IOException |
            CertificateException |
            NoSuchAlgorithmException e
        ) {
            Log.v("ethereumj", e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    @SuppressWarnings("unused")
    public void createKeyPromise(String alias, Promise promise) {
        try {
            Calendar start = new GregorianCalendar();
            Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(
                    getReactApplicationContext()
            ).setAlias(
                    alias
            ).setSubject(
                    new X500Principal("CN=" + alias)
            ).setSerialNumber(
                    BigInteger.valueOf(1337)
            ).setStartDate(
                    start.getTime()
            ).setEndDate(
                    end.getTime()
            ).build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            kpg.initialize(new ECGenParameterSpec("secp256k1"));
            KeyPair kp = kpg.generateKeyPair();

            WritableMap wm = Arguments.createMap();
            wm.putString("public", kp.getPublic().toString());
            wm.putString("private", kp.getPrivate().toString());
            promise.resolve(wm);
        } catch (
            NoSuchProviderException |
            NoSuchAlgorithmException |
            InvalidAlgorithmParameterException e
        ) {
            promise.reject(e);
        }
    }

}
