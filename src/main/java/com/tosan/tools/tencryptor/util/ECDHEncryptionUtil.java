package com.tosan.tools.tencryptor.util;

import com.tosan.tools.tencryptor.exception.EncryptionException;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * @author Hajihosseinkhani
 * @since 17/05/2022
 **/
public class ECDHEncryptionUtil {
    private static final Logger log = LoggerFactory.getLogger(ECDHEncryptionUtil.class);

    public static String encryptByAES(String text, String publicKey, KeyStore keyStore, String privateKeyPassword, String alias) {
        byte[] key = generateSharedKey(publicKey, keyStore, privateKeyPassword, alias);
        byte[] encryptedDataBytes = encryptSymmetric(text.getBytes(StandardCharsets.UTF_8), key, AESEngine.newInstance());
        return new String(Base64.encode(encryptedDataBytes));
    }

    public static byte[] decryptByAES(String encodedText, String publicKey, KeyStore keyStore, String privateKeyPassword, String alias) {
        byte[] key = generateSharedKey(publicKey, keyStore, privateKeyPassword, alias);
        try {
            return decryptSymmetric(Base64.decode(encodedText), key, AESEngine.newInstance());
        } catch (Exception e) {
            throw new EncryptionException("Can not decryptSymmetric text (with AES)", e);
        }
    }

    public static byte[] generateSharedKey(String publicKeyEncoded, KeyStore keyStore, String privateKeyPassword, String alias) {
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());
            ECPrivateKeyParameters ecdhPrivateKeyParameters = (ECPrivateKeyParameters) (PrivateKeyFactory.createKey(privateKey.getEncoded()));

            byte[] result = new byte[16];
            log.debug("Start generating symmetric-key from ECDH keyAgreement");
            ECCurve ecCurve = ecdhPrivateKeyParameters.getParameters().getCurve();
            ECDomainParameters ecDomainParameters = ecdhPrivateKeyParameters.getParameters();
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
                    ecCurve.decodePoint(Base64.decode(publicKeyEncoded)),
                    ecDomainParameters);

            BasicAgreement agree = new ECDHBasicAgreement();
            agree.init(ecdhPrivateKeyParameters);
            BigInteger biKeyAgreement = agree.calculateAgreement(publicKey);
            byte[] keyAgreement = asUnsignedByteArray(getFieldSize(ecdhPrivateKeyParameters), biKeyAgreement);

            SHA1Digest sha1Digest = new SHA1Digest();
            sha1Digest.update(keyAgreement, 0, keyAgreement.length);
            byte[] hashKeyAgreement = new byte[sha1Digest.getDigestSize()];
            sha1Digest.doFinal(hashKeyAgreement, 0);
            System.arraycopy(hashKeyAgreement, 0, result, 0, result.length);
            log.debug("Symmetric-key generated from ECDH keyAgreement");

            return result;
        } catch (Exception e) {
            throw new EncryptionException("Can not generate symmetric-key from ECDH keyAgreement", e);
        }
    }

    private static byte[] asUnsignedByteArray(int length, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            if (bytes.length - 1 > length) {
                throw new IllegalArgumentException("standard length exceeded for value");
            }

            byte[] tmp = new byte[length];
            System.arraycopy(bytes, 1, tmp, tmp.length - (bytes.length - 1), bytes.length - 1);
            return tmp;
        } else {
            if (bytes.length == length) {
                return bytes;
            }
            if (bytes.length > length) {
                throw new IllegalArgumentException("standard length exceeded for value");
            }
            byte[] tmp = new byte[length];
            System.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
            return tmp;
        }
    }

    private static int getFieldSize(ECPrivateKeyParameters ecdhPrivateKeyParameters) {
        return (ecdhPrivateKeyParameters.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    private static byte[] decryptSymmetric(byte[] data, byte[] key, BlockCipher engine) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine));
        cipher.init(false, new KeyParameter(key));
        return callCipher(cipher, data);
    }

    private static byte[] encryptSymmetric(byte[] data, byte[] key, BlockCipher engine) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine));
        cipher.init(true, new KeyParameter(key));
        return callCipher(cipher, data);
    }

    private static byte[] callCipher(BufferedBlockCipher cipher, byte[] data) {
        int size = cipher.getOutputSize(data.length);
        byte[] result = new byte[size];
        int olen = cipher.processBytes(data, 0, data.length, result, 0);
        try {
            olen += cipher.doFinal(result, olen);
        } catch (InvalidCipherTextException e) {
            throw new EncryptionException("Can not decrypt text", e);
        }
        if (olen < size) {
            byte[] tmp = new byte[olen];
            System.arraycopy(result, 0, tmp, 0, olen);
            result = tmp;
        }
        return result;
    }
}
