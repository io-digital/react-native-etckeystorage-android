package za.co.io.etckeystorage;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
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
import java.util.Enumeration;

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
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            kpg.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias, KeyProperties.PURPOSE_SIGN
                    ).setAlgorithmParameterSpec(
                            new ECGenParameterSpec("secp256k1")
                    ).build()
            );
            KeyPair kp = kpg.generateKeyPair();
            WritableMap wm = Arguments.createMap();
            wm.putString("public", Hex.toHexString(kp.getPublic().getEncoded()));
            wm.putString("private", Hex.toHexString(kp.getPrivate().getEncoded()));
            promise.resolve(wm);
        } catch (
            NoSuchProviderException |
            NoSuchAlgorithmException |
            InvalidAlgorithmParameterException e
        ) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @SuppressWarnings("unused")
    public void createKeyNoKeyStorePromise(String alias, Promise promise) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias, KeyProperties.PURPOSE_SIGN
                    ).setAlgorithmParameterSpec(
                            new ECGenParameterSpec("secp256k1")
                    ).build()
            );
            KeyPair kp = kpg.generateKeyPair();
            WritableMap wm = Arguments.createMap();
            wm.putString("public", Hex.toHexString(kp.getPublic().getEncoded()));
            wm.putString("private", Hex.toHexString(kp.getPrivate().getEncoded()));
            promise.resolve(wm);
        } catch (
            NoSuchAlgorithmException |
            InvalidAlgorithmParameterException e
        ) {
            promise.reject(e);
        }
    }

}
