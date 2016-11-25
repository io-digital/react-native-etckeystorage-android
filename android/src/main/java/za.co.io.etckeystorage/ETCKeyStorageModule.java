package za.co.io.etckeystorage;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import org.spongycastle.util.encoders.Hex;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

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
}
