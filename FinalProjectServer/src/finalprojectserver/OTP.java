
package FinalProjectServer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
* This class implements a basic TOTP primitive. The implementation
 * follows the guidelines specified in RFC 6238.

 * @author Zach Kissel
 */
public class OTP extends OTP_Super{
    private String key;
    private long baseTime;
    private final int TIME_DURATION = 30;
    
    public OTP() throws NoSuchAlgorithmException, InvalidKeyException
    {
        super("HmacSHA1");
        baseTime = 0;
    }
    public OTP(long baseTime, String key) throws NoSuchAlgorithmException, InvalidKeyException
    {
        super("HmacSHA1", key);
        this.baseTime = baseTime;
    }

    @Override
    public String nextOTP() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean verify(String otp) {
        // Current token window.
        long durationCount = (long) Math.floor(
            (Instant.now().getEpochSecond() - baseTime) / TIME_DURATION);

        // previous token window to account for transmission delay.
        long durationCountWindow = (long) Math.floor(
            (Instant.now().getEpochSecond() - baseTime - TIME_DURATION)/
            TIME_DURATION);

        return (generateOTP(durationCount).equals(otp) ||
                generateOTP(durationCountWindow).equals(otp));
    }
}