package com.tosan.tools.tencryptor.unit;

import com.tosan.tools.tencryptor.encryptor.TosanEncryptor;
import com.tosan.tools.tencryptor.exception.EncryptionException;
import com.tosan.tools.tencryptor.exception.InvalidAlgorithmException;
import com.tosan.tools.tencryptor.exception.InvalidKeyException;
import org.junit.jupiter.api.Test;

import static com.tosan.tools.tencryptor.encryptor.TosanEncryptor.PKCS7_ALGORITHM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Soltanmohammadi
 * @since 10/27/2015
 */
public class TosanEncryptorUTest {
    private static final String privateData = "private data";
    private static final String emptyString = "";
    private static final String blankString = "   ";

    @Test
    public void testEncryptionProcess_encryptWithNonDefaultAlgorithm_encrypted() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", "DES");
        String encryptedData = TosanEncryptor.encryptText(privateData);
        String decryptedData = TosanEncryptor.decryptText(encryptedData);

        assertEquals(decryptedData, privateData);
    }

    @Test
    public void testEncryptionProcess_encryptWith_NonDefaultAlgorithmWithIV_Algorithm_encrypted() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("1234567812345678", PKCS7_ALGORITHM);
        String encryptedData = TosanEncryptor.encryptText(privateData);
        String decryptedData = TosanEncryptor.decryptText(encryptedData);

        assertEquals(decryptedData, privateData);
    }

    @Test
    public void testEncryptionProcess_encryptWithDefaultAlgorithm_encrypted() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("1234567812345678");
        String encryptedData = TosanEncryptor.encryptText(privateData);
        String decryptedData = TosanEncryptor.decryptText(encryptedData);

        assertEquals(decryptedData, privateData);
    }

    @Test
    public void testEncryptionProcess_setKeyInHalfway_encrypted() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", "DES");
        TosanEncryptor.setKey("a@5i#9x8");
        String encryptedData = TosanEncryptor.encryptText(privateData);
        String decryptedData = TosanEncryptor.decryptText(encryptedData);

        assertEquals(decryptedData, privateData);
    }

    @Test
    public void testEncryptionProcess_changeKeyAfterEncryption_exceptionThrown() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", "DES");
        String encryptedData = TosanEncryptor.encryptText(privateData);
        TosanEncryptor.setKey("a@5i#9x8");
        assertThrows(InvalidKeyException.class, () -> TosanEncryptor.decryptText(encryptedData));
    }

    @Test
    public void testEncryptionProcess_BadAlgorithmName_exceptionThrown() {
        assertThrows(InvalidAlgorithmException.class, () -> new TosanEncryptor("a@3i#6O8", "ABC"));
    }

    @Test
    public void testEncryptionProcess_InvalidAlgorithmKey_exceptionThrown() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8N", "DES");
        assertThrows(InvalidKeyException.class, () -> TosanEncryptor.encryptText(privateData));
    }

    @Test
    public void testEncryptionProcess_decryptEmptyString_returnEmptyString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        String decryptedData = TosanEncryptor.decryptText(emptyString);
        assertEquals(decryptedData, emptyString);
    }

    @Test
    public void testEncryptionProcess_decryptEmptyStringWithKey_returnEmptyString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        String decryptedData = TosanEncryptor.decryptText("a@3i#6O8", emptyString);
        assertEquals(decryptedData, emptyString);
    }

    @Test
    public void testEncryptionProcess_decryptBlankString_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        String decryptedData = TosanEncryptor.decryptText(blankString);
        assertEquals(decryptedData, blankString);
    }

    @Test
    public void testEncryptionProcess_decryptBlankStringWithKey_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        String decryptedData = TosanEncryptor.decryptText("a@3i#6O8", blankString);
        assertEquals(decryptedData, blankString);
    }

    @Test
    public void testEncryptionProcess_decryptNull_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        assertThrows(EncryptionException.class, () -> TosanEncryptor.decryptText(null));
    }

    @Test
    public void testEncryptionProcess_decryptNullWithKey_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        assertThrows(EncryptionException.class, () -> TosanEncryptor.decryptText("a@3i#6O8", null));
    }

    @Test
    public void testEncryptionProcess_encryptEmptyString_returnEmptyString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        assertThrows(EncryptionException.class, () -> TosanEncryptor.encryptText(emptyString));
    }

    @Test
    public void testEncryptionProcess_encryptBlankString_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        assertThrows(EncryptionException.class, () -> TosanEncryptor.encryptText(blankString));
    }

    @Test
    public void testEncryptionProcess_encryptNull_returnBlankString() {
        TosanEncryptor TosanEncryptor = new TosanEncryptor("a@3i#6O8", PKCS7_ALGORITHM);
        assertThrows(EncryptionException.class, () -> TosanEncryptor.encryptText(null));
    }
}
