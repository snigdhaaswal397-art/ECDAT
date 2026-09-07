import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class LegacyAuthService {

    public void hashMD5(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data.getBytes());
    }

    public void hashSHA1(String data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(data.getBytes());
    }

    public KeyPairGenerator generateRSAKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen;
    }

    public byte[] encryptAES(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(data);
    }

    public void signECDSA() throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(null);
    }
}
