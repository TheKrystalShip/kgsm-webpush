using System.Security.Cryptography;
using System.Text;
using TheKrystalShip.KGSM.WebPush;

namespace TheKrystalShip.KGSM.WebPush.Tests;

/// <summary>
/// RFC 8291 encryption, checked by <b>decrypting</b> it the way a browser does.
/// <para>
/// This is the part of the package that cannot be verified by looking at it: a ciphertext is opaque, and
/// an encoding mistake produces bytes that are the right length and the wrong message. So the test is a
/// receiver — it derives the same keys from the subscription's private half and reads the plaintext back,
/// which is exactly what fails if the salt, the record size, the key-info labels or the padding are wrong.
/// </para>
/// </summary>
public sealed class WebPushCryptoTests
{
    /// <summary>A subscription the way a browser mints one: a P-256 pair plus 16 random auth bytes.</summary>
    private static (string P256dh, string Auth, ECDiffieHellman Key) Subscription()
    {
        ECDiffieHellman key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters p = key.ExportParameters(false);
        byte[] point = new byte[65];
        point[0] = 0x04;
        p.Q.X!.CopyTo(point, 33 - p.Q.X!.Length);
        p.Q.Y!.CopyTo(point, 65 - p.Q.Y!.Length);

        byte[] auth = RandomNumberGenerator.GetBytes(16);
        return (WebPushCrypto.ToBase64Url(point), WebPushCrypto.ToBase64Url(auth), key);
    }

    /// <summary>
    /// The receiving half of RFC 8291 §3.4 / RFC 8188 §2, written out here so the test proves the
    /// wire format rather than re-using the sender's own idea of it.
    /// </summary>
    private static byte[] Decrypt(byte[] message, ECDiffieHellman receiver, byte[] authSecret)
    {
        // aes128gcm header: salt(16) | rs(4, big-endian) | idlen(1) | keyid(idlen)
        ReadOnlySpan<byte> span = message;
        byte[] salt = span[..16].ToArray();
        int idLen = span[20];
        byte[] senderPublic = span.Slice(21, idLen).ToArray();
        byte[] ciphertext = span[(21 + idLen)..].ToArray();

        using var sender = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = senderPublic[1..33], Y = senderPublic[33..65] },
        });

        byte[] shared = receiver.DeriveRawSecretAgreement(sender.PublicKey);

        ECParameters mine = receiver.ExportParameters(false);
        byte[] receiverPublic = new byte[65];
        receiverPublic[0] = 0x04;
        mine.Q.X!.CopyTo(receiverPublic, 33 - mine.Q.X!.Length);
        mine.Q.Y!.CopyTo(receiverPublic, 65 - mine.Q.Y!.Length);

        // PRK = HKDF(auth_secret, ecdh_secret, "WebPush: info" || ua_public || as_public)
        byte[] keyInfo = [.. Encoding.UTF8.GetBytes("WebPush: info\0"), .. receiverPublic, .. senderPublic];
        byte[] ikm = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, authSecret, keyInfo);

        byte[] cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, salt,
            Encoding.UTF8.GetBytes("Content-Encoding: aes128gcm\0"));
        byte[] nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 12, salt,
            Encoding.UTF8.GetBytes("Content-Encoding: nonce\0"));

        byte[] plain = new byte[ciphertext.Length - 16];
        using var gcm = new AesGcm(cek, 16);
        gcm.Decrypt(nonce, ciphertext[..^16], ciphertext[^16..], plain);

        // The record's delimiter: 0x02 for the last record, which every message here is.
        int end = plain.Length;
        while (end > 0 && plain[end - 1] == 0x00) end--;
        Assert.Equal(0x02, plain[end - 1]);
        return plain[..(end - 1)];
    }

    [Fact]
    public void A_message_round_trips_to_the_bytes_that_went_in()
    {
        (string p256dh, string auth, ECDiffieHellman key) = Subscription();
        using (key)
        {
            byte[] payload = Encoding.UTF8.GetBytes("""{"title":"romestead crashed","body":"auto-restarting"}""");

            byte[] message = WebPushCrypto.Encrypt(
                payload, WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));

            Assert.Equal(payload, Decrypt(message, key, WebPushCrypto.FromBase64Url(auth)));
        }
    }

    [Fact]
    public void The_same_payload_twice_is_two_different_ciphertexts()
    {
        // The salt and the ephemeral key are per-message. Two identical messages producing identical
        // bytes would mean one of them is fixed, which is the failure that silently removes the
        // encryption's whole point.
        (string p256dh, string auth, ECDiffieHellman key) = Subscription();
        using (key)
        {
            byte[] payload = Encoding.UTF8.GetBytes("same");
            byte[] a = WebPushCrypto.Encrypt(payload, WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));
            byte[] b = WebPushCrypto.Encrypt(payload, WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));

            Assert.NotEqual(a, b);
            Assert.Equal(payload, Decrypt(a, key, WebPushCrypto.FromBase64Url(auth)));
            Assert.Equal(payload, Decrypt(b, key, WebPushCrypto.FromBase64Url(auth)));
        }
    }

    [Fact]
    public void An_empty_payload_still_produces_a_readable_message()
    {
        (string p256dh, string auth, ECDiffieHellman key) = Subscription();
        using (key)
        {
            byte[] message = WebPushCrypto.Encrypt(
                [], WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));
            Assert.Empty(Decrypt(message, key, WebPushCrypto.FromBase64Url(auth)));
        }
    }

    [Fact]
    public void A_payload_with_multibyte_text_survives_intact()
    {
        (string p256dh, string auth, ECDiffieHellman key) = Subscription();
        using (key)
        {
            byte[] payload = Encoding.UTF8.GetBytes("日本語 — emoji 🎮 — ünïcödé");
            byte[] message = WebPushCrypto.Encrypt(
                payload, WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));

            Assert.Equal(payload, Decrypt(message, key, WebPushCrypto.FromBase64Url(auth)));
        }
    }

    [Fact]
    public void The_message_carries_the_aes128gcm_header_a_browser_parses()
    {
        (string p256dh, string auth, ECDiffieHellman key) = Subscription();
        using (key)
        {
            byte[] message = WebPushCrypto.Encrypt(
                Encoding.UTF8.GetBytes("x"), WebPushCrypto.FromBase64Url(p256dh), WebPushCrypto.FromBase64Url(auth));

            // salt(16) | rs(4) | idlen(1) | keyid — and the key id is the sender's uncompressed point.
            Assert.True(message.Length > 21 + 65);
            Assert.Equal(65, message[20]);
            Assert.Equal(0x04, message[21]);
        }
    }

    [Theory]
    [InlineData("not base64url at all!!")]
    [InlineData("")]
    public void Unusable_subscription_keys_are_refused_rather_than_sent(string p256dh)
    {
        // The sender turns this into "retire the row": no retry fixes a malformed key, and failing
        // against it forever is the alternative.
        Assert.ThrowsAny<Exception>(() => WebPushCrypto.Encrypt(
            [1, 2, 3], WebPushCrypto.FromBase64Url(p256dh), RandomNumberGenerator.GetBytes(16)));
    }

    [Fact]
    public void Base64url_round_trips_without_padding()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(33);   // a length that would pad in plain base64
        string encoded = WebPushCrypto.ToBase64Url(bytes);

        Assert.DoesNotContain('=', encoded);
        Assert.Equal(bytes, WebPushCrypto.FromBase64Url(encoded));
    }
}
