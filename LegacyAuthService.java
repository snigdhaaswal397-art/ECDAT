import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class LegacyAuthService {

    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    public byte[] checksumData(byte[] data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return sha1.digest(data);
    }

    public KeyPairGenerator generateRsaKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen;
    }

    public Cipher encryptPayload() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher;
    }

    public Signature signData() throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        return sig;
    }
}
