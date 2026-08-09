package io.github.easy4j.jwt.utils;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecretKeyUtils}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("SecretKeyUtils Tests")
class SecretKeyUtilsTest {

    @Test
    @DisplayName("should generate AES secret key")
    void shouldGenerateAesSecretKey() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genSecretKey(SecretKeyUtils.KEY_AES);
        assertThat(key).isNotNull();
        assertThat(key.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    @DisplayName("should generate AES secret key with key size")
    void shouldGenerateAesSecretKeyWithKeySize() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genSecretKey(SecretKeyUtils.KEY_AES, 128);
        assertThat(key).isNotNull();
        assertThat(key.getEncoded()).hasSize(16); // 128 bits = 16 bytes
    }

    @Test
    @DisplayName("should generate AES secret key with seed")
    void shouldGenerateAesSecretKeyWithSeed() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genSecretKey("mySeed", SecretKeyUtils.KEY_AES, 128);
        assertThat(key).isNotNull();
        assertThat(key.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    @DisplayName("should generate secret key from string")
    void shouldGenerateSecretKeyFromString() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genSecretKey("mySecretKey12345", SecretKeyUtils.KEY_AES);
        assertThat(key).isNotNull();
        assertThat(key.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    @DisplayName("should generate secret key from bytes")
    void shouldGenerateSecretKeyFromBytes() throws GeneralSecurityException {
        byte[] keyBytes = new byte[16];
        SecretKey key = SecretKeyUtils.genSecretKey(keyBytes, SecretKeyUtils.KEY_AES);
        assertThat(key).isNotNull();
    }

    @Test
    @DisplayName("should generate binary secret key")
    void shouldGenerateBinarySecretKey() throws GeneralSecurityException {
        byte[] keyBytes = SecretKeyUtils.genBinarySecretKey(SecretKeyUtils.KEY_AES);
        assertThat(keyBytes).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should generate binary secret key with size")
    void shouldGenerateBinarySecretKeyWithSize() throws GeneralSecurityException {
        byte[] keyBytes = SecretKeyUtils.genBinarySecretKey(SecretKeyUtils.KEY_AES, 128);
        assertThat(keyBytes).hasSize(16);
    }

    @Test
    @DisplayName("should generate binary secret key with seed")
    void shouldGenerateBinarySecretKeyWithSeed() throws GeneralSecurityException {
        byte[] keyBytes = SecretKeyUtils.genBinarySecretKey("seed", SecretKeyUtils.KEY_AES, 128);
        assertThat(keyBytes).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should generate RSA key pair")
    void shouldGenerateRsaKeyPair() throws GeneralSecurityException {
        KeyPair keyPair = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024);
        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    @DisplayName("should generate RSA key pair with default size")
    void shouldGenerateRsaKeyPairWithDefaultSize() throws GeneralSecurityException {
        KeyPair keyPair = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA);
        assertThat(keyPair).isNotNull();
    }

    @Test
    @DisplayName("should generate RSA key pair with seed")
    void shouldGenerateRsaKeyPairWithSeed() throws GeneralSecurityException {
        KeyPair keyPair = SecretKeyUtils.genKeyPair("seed", SecretKeyUtils.KEY_RSA, 1024);
        assertThat(keyPair).isNotNull();
    }

    @Test
    @DisplayName("should generate public key from bytes")
    void shouldGeneratePublicKeyFromBytes() throws GeneralSecurityException {
        KeyPair keyPair = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024);
        byte[] pubKeyBytes = keyPair.getPublic().getEncoded();
        PublicKey publicKey = SecretKeyUtils.genPublicKey(SecretKeyUtils.KEY_RSA, pubKeyBytes);
        assertThat(publicKey).isNotNull();
    }

    @Test
    @DisplayName("should generate private key from bytes")
    void shouldGeneratePrivateKeyFromBytes() throws GeneralSecurityException {
        KeyPair keyPair = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024);
        byte[] priKeyBytes = keyPair.getPrivate().getEncoded();
        PrivateKey privateKey = SecretKeyUtils.genPrivateKey(SecretKeyUtils.KEY_RSA, priKeyBytes);
        assertThat(privateKey).isNotNull();
    }

    @Test
    @DisplayName("should generate secure random without seed")
    void shouldGenerateSecureRandomWithoutSeed() {
        SecureRandom random = SecretKeyUtils.genSecureRandom();
        assertThat(random).isNotNull();
    }

    @Test
    @DisplayName("should generate secure random with seed")
    void shouldGenerateSecureRandomWithSeed() {
        SecureRandom random = SecretKeyUtils.genSecureRandom("mySeed");
        assertThat(random).isNotNull();
    }

    @Test
    @DisplayName("should generate secure random with null seed")
    void shouldGenerateSecureRandomWithNullSeed() {
        SecureRandom random = SecretKeyUtils.genSecureRandom(null);
        assertThat(random).isNotNull();
    }

    @Test
    @DisplayName("should generate secure random with empty seed")
    void shouldGenerateSecureRandomWithEmptySeed() {
        SecureRandom random = SecretKeyUtils.genSecureRandom("");
        assertThat(random).isNotNull();
    }

    @Test
    @DisplayName("should generate random key")
    void shouldGenerateRandomKey() {
        byte[] key = SecretKeyUtils.genRandomKey(32);
        assertThat(key).isNotNull().hasSize(32);
    }

    @Test
    @DisplayName("should generate random key with seed")
    void shouldGenerateRandomKeyWithSeed() {
        byte[] key = SecretKeyUtils.genRandomKey("seed", 32);
        assertThat(key).isNotNull().hasSize(32);
    }

    @Test
    @DisplayName("should generate PBE key")
    void shouldGeneratePbeKey() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genPBEKey("password", "PBEWithMD5AndDES");
        assertThat(key).isNotNull();
    }

    @Test
    @DisplayName("should generate PBE key from char array")
    void shouldGeneratePbeKeyFromCharArray() throws GeneralSecurityException {
        SecretKey key = SecretKeyUtils.genPBEKey("password".toCharArray(), "PBEWithMD5AndDES");
        assertThat(key).isNotNull();
    }

    @Test
    @DisplayName("should have correct algorithm constants")
    void shouldHaveCorrectAlgorithmConstants() {
        assertThat(SecretKeyUtils.KEY_AES).isEqualTo("AES");
        assertThat(SecretKeyUtils.KEY_BASE64).isEqualTo("Base64");
        assertThat(SecretKeyUtils.KEY_DES).isEqualTo("DES");
        assertThat(SecretKeyUtils.KEY_DESEDE).isEqualTo("DESede");
        assertThat(SecretKeyUtils.KEY_RSA).isEqualTo("RSA");
        assertThat(SecretKeyUtils.KEY_ECDSA).isEqualTo("ECDSA");
    }

    @Test
    @DisplayName("should have correct size constants")
    void shouldHaveCorrectSizeConstants() {
        assertThat(SecretKeyUtils.KEY_SIZE).isEqualTo(128);
        assertThat(SecretKeyUtils.CACHE_SIZE).isEqualTo(1024);
    }

    @Test
    @DisplayName("should generate secret key base64")
    void shouldGenerateSecretKeyBase64() throws Exception {
        String base64Key = SecretKeyUtils.genSecretKeyBase64(SecretKeyUtils.KEY_AES, 128);
        assertThat(base64Key).isNotNull().isNotEmpty();
    }
}
