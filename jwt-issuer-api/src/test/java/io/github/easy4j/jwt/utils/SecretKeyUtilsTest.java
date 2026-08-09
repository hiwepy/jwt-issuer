package io.github.easy4j.jwt.utils;

import java.security.*;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecretKeyUtils Tests")
class SecretKeyUtilsTest {
    @Test void shouldGenerateAesSecretKey() throws Exception { assertThat(SecretKeyUtils.genSecretKey(SecretKeyUtils.KEY_AES)).isNotNull(); }
    @Test void shouldGenerateAesSecretKeyWithKeySize() throws Exception { assertThat(SecretKeyUtils.genSecretKey(SecretKeyUtils.KEY_AES, 128).getEncoded()).hasSize(16); }
    @Test void shouldGenerateAesSecretKeyWithSeed() throws Exception { assertThat(SecretKeyUtils.genSecretKey("seed", SecretKeyUtils.KEY_AES, 128)).isNotNull(); }
    @Test void shouldGenerateSecretKeyFromString() throws Exception { assertThat(SecretKeyUtils.genSecretKey("mykey12345678901", SecretKeyUtils.KEY_AES)).isNotNull(); }
    @Test void shouldGenerateSecretKeyFromBytes() throws Exception { assertThat(SecretKeyUtils.genSecretKey(new byte[16], SecretKeyUtils.KEY_AES)).isNotNull(); }
    @Test void shouldGenerateBinarySecretKey() throws Exception { assertThat(SecretKeyUtils.genBinarySecretKey(SecretKeyUtils.KEY_AES)).isNotNull().isNotEmpty(); }
    @Test void shouldGenerateBinarySecretKeyWithSize() throws Exception { assertThat(SecretKeyUtils.genBinarySecretKey(SecretKeyUtils.KEY_AES, 128)).hasSize(16); }
    @Test void shouldGenerateRsaKeyPair() throws Exception { var kp = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024); assertThat(kp.getPublic()).isNotNull(); assertThat(kp.getPrivate()).isNotNull(); }
    @Test void shouldGenerateRsaKeyPairWithDefaultSize() throws Exception { assertThat(SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA)).isNotNull(); }
    @Test void shouldGenerateRsaKeyPairWithSeed() throws Exception { assertThat(SecretKeyUtils.genKeyPair("seed", SecretKeyUtils.KEY_RSA, 1024)).isNotNull(); }
    @Test void shouldGeneratePublicKeyFromBytes() throws Exception { var kp = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024); assertThat(SecretKeyUtils.genPublicKey(SecretKeyUtils.KEY_RSA, kp.getPublic().getEncoded())).isNotNull(); }
    @Test void shouldGeneratePrivateKeyFromBytes() throws Exception { var kp = SecretKeyUtils.genKeyPair(SecretKeyUtils.KEY_RSA, 1024); assertThat(SecretKeyUtils.genPrivateKey(SecretKeyUtils.KEY_RSA, kp.getPrivate().getEncoded())).isNotNull(); }
    @Test void shouldGenerateSecureRandomWithoutSeed() { assertThat(SecretKeyUtils.genSecureRandom()).isNotNull(); }
    @Test void shouldGenerateSecureRandomWithSeed() { assertThat(SecretKeyUtils.genSecureRandom("seed")).isNotNull(); }
    @Test void shouldGenerateRandomKey() { assertThat(SecretKeyUtils.genRandomKey(32)).hasSize(32); }
    @Test void shouldGenerateRandomKeyWithSeed() { assertThat(SecretKeyUtils.genRandomKey("seed", 32)).hasSize(32); }
    @Test void shouldHaveCorrectAlgorithmConstants() { assertThat(SecretKeyUtils.KEY_AES).isEqualTo("AES"); assertThat(SecretKeyUtils.KEY_RSA).isEqualTo("RSA"); assertThat(SecretKeyUtils.KEY_ECDSA).isEqualTo("ECDSA"); }
    @Test void shouldHaveCorrectSizeConstants() { assertThat(SecretKeyUtils.KEY_SIZE).isEqualTo(128); assertThat(SecretKeyUtils.CACHE_SIZE).isEqualTo(1024); }
    @Test void shouldGenerateSecretKeyBase64() throws Exception { assertThat(SecretKeyUtils.genSecretKeyBase64(SecretKeyUtils.KEY_AES, 128)).isNotNull().isNotEmpty(); }
}
