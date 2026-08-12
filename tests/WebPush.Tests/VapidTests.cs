using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TheKrystalShip.KGSM.WebPush;

namespace TheKrystalShip.KGSM.WebPush.Tests;

/// <summary>
/// The VAPID identity and the token it signs.
/// <para>
/// Two things here are the kind of wrong that produces a working-looking header every push service
/// rejects: a DER-encoded signature where ES256 wants fixed-width r‖s, and a full endpoint URL where the
/// audience wants an origin. Both are pinned.
/// </para>
/// </summary>
public sealed class VapidTests
{
    private static readonly Uri Endpoint = new("https://fcm.googleapis.com/fcm/send/abc123?x=1");
    private static readonly DateTimeOffset Now = new(2026, 8, 12, 12, 0, 0, TimeSpan.Zero);

    private static (string Header, string Payload, byte[] Signature) Parts(string authorization)
    {
        string jwt = authorization["vapid t=".Length..authorization.IndexOf(", k=", StringComparison.Ordinal)];
        string[] segments = jwt.Split('.');
        return (segments[0], segments[1], WebPushCrypto.FromBase64Url(segments[2]));
    }

    private static JsonElement Claims(string authorization) =>
        JsonDocument.Parse(WebPushCrypto.FromBase64Url(Parts(authorization).Payload)).RootElement;

    [Fact]
    public void A_generated_pair_is_the_shape_the_browser_expects()
    {
        VapidKeyPair keys = VapidKeyPair.Generate();

        // 65 uncompressed bytes starting 0x04 is exactly what applicationServerKey takes; anything else
        // is refused by the browser at subscribe time, before this host ever sends a thing.
        byte[] pub = WebPushCrypto.FromBase64Url(keys.PublicKey);
        Assert.Equal(65, pub.Length);
        Assert.Equal(0x04, pub[0]);
        Assert.Equal(32, WebPushCrypto.FromBase64Url(keys.PrivateKey).Length);
    }

    [Fact]
    public void Two_pairs_are_not_the_same_pair()
    {
        Assert.NotEqual(VapidKeyPair.Generate().PublicKey, VapidKeyPair.Generate().PublicKey);
    }

    [Fact]
    public void The_audience_is_the_ORIGIN_never_the_endpoint()
    {
        // The full path carries the subscription id. Sending it would leak that into a token the push
        // service logs — and be rejected besides.
        JsonElement claims = Claims(VapidSigner.Authorization(VapidKeyPair.Generate(), Endpoint, "https://panel.test", Now));

        Assert.Equal("https://fcm.googleapis.com", claims.GetProperty("aud").GetString());
        Assert.Equal("https://panel.test", claims.GetProperty("sub").GetString());
    }

    [Fact]
    public void The_token_expires_inside_the_ceiling_the_RFC_puts_on_it()
    {
        JsonElement claims = Claims(VapidSigner.Authorization(VapidKeyPair.Generate(), Endpoint, "https://panel.test", Now));

        long exp = claims.GetProperty("exp").GetInt64();
        long lifetime = exp - Now.ToUnixTimeSeconds();

        Assert.InRange(lifetime, 1, 24 * 60 * 60);   // some services enforce the 24h ceiling strictly
    }

    [Fact]
    public void The_signature_is_fixed_width_r_and_s_not_DER()
    {
        // A DER signature is well-formed and every push service rejects it, which is the worst kind of
        // bug: nothing is malformed, nothing throws, nothing arrives.
        string auth = VapidSigner.Authorization(VapidKeyPair.Generate(), Endpoint, "https://panel.test", Now);
        Assert.Equal(64, Parts(auth).Signature.Length);
    }

    [Fact]
    public void The_signature_verifies_against_the_key_in_the_header()
    {
        VapidKeyPair keys = VapidKeyPair.Generate();
        string auth = VapidSigner.Authorization(keys, Endpoint, "https://panel.test", Now);
        (string header, string payload, byte[] signature) = Parts(auth);

        // The k= parameter is what the push service verifies with, so it has to be the pair that signed.
        Assert.EndsWith(", k=" + keys.PublicKey, auth, StringComparison.Ordinal);

        byte[] pub = WebPushCrypto.FromBase64Url(keys.PublicKey);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
        });

        Assert.True(verifier.VerifyData(
            Encoding.UTF8.GetBytes(header + "." + payload), signature, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void The_header_says_ES256()
    {
        string auth = VapidSigner.Authorization(VapidKeyPair.Generate(), Endpoint, "https://panel.test", Now);
        JsonElement header = JsonDocument.Parse(WebPushCrypto.FromBase64Url(Parts(auth).Header)).RootElement;

        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
    }

    [Fact]
    public void A_subject_carrying_a_quote_still_produces_valid_JSON()
    {
        // The claims are written out rather than serialized, so the escaping is this code's job and a
        // hostile-looking subject is the case that proves it is being done.
        string auth = VapidSigner.Authorization(
            VapidKeyPair.Generate(), Endpoint, """mailto:a"b\c@example.com""", Now);

        Assert.Equal("""mailto:a"b\c@example.com""", Claims(auth).GetProperty("sub").GetString());
    }

    [Fact]
    public void Base64url_carries_no_padding_and_no_url_unsafe_characters()
    {
        // A '+' or '/' in a JWT segment is what turns a valid token into a 400 from the push service.
        string auth = VapidSigner.Authorization(VapidKeyPair.Generate(), Endpoint, "https://panel.test", Now);
        string jwt = auth["vapid t=".Length..auth.IndexOf(", k=", StringComparison.Ordinal)];

        Assert.DoesNotContain('=', jwt);
        Assert.DoesNotContain('+', jwt);
        Assert.DoesNotContain('/', jwt);
    }
}
