
package FinalProjectServer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This abstract class provides the interface for a basic OTP primitive.
 * Our base construction uses the foundations of RFC 4226.
 *
 * @author Zach Kissel

 */
public abstract class OTP_Super {
    private Mac hmac;
    private SecretKey skey;

  /**
   * This constructor creates a new hash OTP object with a random
   * key and an intial starting counter value of 0.
   *
   * @param hmacAlgo  a string representing the algorithm to use.
   *
   * @throws NoSuchAlgorithmException when the hmacAlgo is unknown.
   * @throws InvalidKeyException when the generated key is bad.
   */
  public OTP_Super(String hmacAlgo) throws
     NoSuchAlgorithmException, InvalidKeyException
  {
    hmac = Mac.getInstance(hmacAlgo);
    skey = KeyGenerator.getInstance(hmacAlgo).generateKey();
    hmac.init(skey);
  }

  /**
   * This constructor creates a new hash OPT object with the given
   * key using the specified algorithm.
   *
   * @param hmacAlgo  a string representing the algorithm to use.
   * @param key the base-64 encoded key.
   *
   * @throws NoSuchAlgorithmException when the hmacAlgo is unknown.
   * @throws InvalidKeyException when the key parameter is not a valid key.
   */
  public OTP_Super(String hmacAlgo, String key) throws
      NoSuchAlgorithmException, InvalidKeyException
  {
    hmac = Mac.getInstance(hmacAlgo);
    skey = new SecretKeySpec(Base64.getDecoder().decode(key), hmacAlgo);
    hmac.init(skey);
  }

  /**
   * Returns the key as a base-64 encoded string.
   *
   * @return the base-64 encode key.
   */
  public String getKey()
  {
    return Base64.getEncoder().encodeToString(skey.getEncoded());
  }

  /**
   * Generates a one-time password using the necessary HMAC. The OTP is
   * returned as a string of 6 digits (potentially with leading zeros).
   * @param ctr the value of the counter to use in generateing the OTP.
   * @return a 6 digit OTP.
   */
  public String generateOTP(long ctr)
  {
    int otp = 0;

    // Generate the digest.
    byte[] digest = hmac.doFinal(longToBytes(ctr));

    // Calculate the offset by looking at the low-order nibble of the
    // high order byte of the digest.
    int offset = (int)(digest[digest.length - 1] & 0x0F);

    // Look at the contiguous 4 bytes starting at the offset and
    // reduce the result mod 10^6 so that we end up with a 6 digit
    // code.
    otp = ((digest[offset] & 0x7F) << 24 |
          (digest[offset + 1] & 0xFF) << 16 |
          (digest[offset + 2] & 0xFF) << 8 |
          (digest[offset + 3] & 0xFF)) % 1000000;

    return String.format("%06d", otp);
  }


  public abstract String nextOTP();
  public abstract boolean verify(String otp);

  ////////////////// PRIVATE METHODS ///////////////////
  /**
   * This method converts a long value into an 8-byte value.
   *
   * @param num the number to conver to bytes.
   * @return an array of 8 bytes representing the number num.
   */
   private byte[] longToBytes(long num)
   {
     byte[] res = new byte[8];

     // Decompose the a long type into byte components.
     for (int i = 7; i >= 0; i--)
     {
      res[i] = (byte)(num & 0xFF);
      num >>= 8;
     }

    return res;
  }

}