package com.tosan.tools.tencryptor.unit;

import com.tosan.tools.tencryptor.exception.EncryptionException;
import com.tosan.tools.tencryptor.util.EncryptionUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Hajihosseinkhani
 * @since 18/05/2022
 **/
public class EncryptionUtilUTest {
    private static KeyStore keyStore;

    @BeforeAll
    public static void init() {
        InputStream inputStream = EncryptionUtilUTest.class.getClassLoader().getResourceAsStream("testKeyStore.jks");
        keyStore = EncryptionUtil.loadKeyStore(inputStream, "keystoresafepassword".toCharArray());
    }

    @Test
    public void testEcdhEncrypt() {
        assertEquals("kXb4e+KNs9JSb+ciEilLNA==", EncryptionUtil.ecdhEncrypt("123",
                "A6HCP3D08c+68im0diKihE5Bf0ZJRlXz6B+1U73XsGWX", keyStore, "keytsn1password", "ec_s1as_tosan"));
    }

    @Test
    public void testEcdhDecrypt() {
        assertEquals("123", new String(EncryptionUtil.ecdhDecrypt("kXb4e+KNs9JSb+ciEilLNA==",
                "A6HCP3D08c+68im0diKihE5Bf0ZJRlXz6B+1U73XsGWX", keyStore, "keytsn1password", "ec_s1as_tosan")));
    }

    @Test
    public void testGenerateHash() {
        assertEquals("C2FC6C6ADF8BA0F575A35F48DF52C0968A3DCD3C577C2769DC2F1035943B975E",
                EncryptionUtil.generateSHA2HashWithSalt("123", "salt"));
    }

    @Test
    public void testGenerateSalt() {
        assertNotNull(EncryptionUtil.generateRandomSalt());
    }

    @Test
    public void testGenerateSHA2HMAC_InputsAreNull_ExpectedEncryptionExceptionIsThrown() {
        assertThrows(EncryptionException.class, () -> EncryptionUtil.generateSH2HMAC(null, null));
    }

    @Test
    public void testGenerateSHA2MAC_HappyScenario() {
        assertEquals("5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0", EncryptionUtil.generateSH2HMAC("data", "key"));
    }
}
