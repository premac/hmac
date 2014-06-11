import sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by premysl on 6/11/14.
 */
public class Hmac {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        System.out.println(hmac("message"));
        System.out.println(hmac("message"));
        System.out.println(hmac("a"));
        System.out.println(hmac("aaaaaa"));
        System.out.println(hmac("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        System.out.println(hmac("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));


        SecretKeySpec key = new SecretKeySpec(
                new byte[16],
                "AES");

        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        System.out.println(new String(cipher.doFinal("message".getBytes("utf-8")), "utf-8"));

    }

    static String hmac(String message) {
        try {
            SecretKeySpec key = new SecretKeySpec(
                    "qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1Idasfadfasfsafdsafad51".getBytes(),
                    "HmacSHA256");

            // Create a MAC object using HMAC-MD5 and initialize with key
            Mac mac = Mac.getInstance(key.getAlgorithm());
            mac.init(key);

            // Encode the string into bytes using utf-8 and digest it
            byte[] utf8 = new byte[0];
            utf8 = message.getBytes("UTF8");
            byte[] digest = mac.doFinal(utf8);

            // If desired, convert the digest into a string
            return new sun.misc.BASE64Encoder().encode(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }



}
