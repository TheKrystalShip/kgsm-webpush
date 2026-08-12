using System.Net;
using System.Net.Http.Headers;

namespace TheKrystalShip.KGSM.WebPush;

/// <summary>The outcome of one push, split by what the caller must DO about it.</summary>
public enum PushOutcome
{
    /// <summary>The push service accepted the message for delivery. It says nothing about whether the
    /// device ever shows it — that is the user agent's business and we never claim otherwise.</summary>
    Accepted,

    /// <summary>The subscription is definitively gone (404/410). Delete the row; it will never work again.</summary>
    Expired,

    /// <summary>A transient or unknown failure. Count it; don't delete on one bad answer.</summary>
    Failed,
}

public sealed record PushResult(PushOutcome Outcome, int? Status, string? Error);

/// <summary>
/// One browser's push credential, as the browser itself minted it.
/// </summary>
/// <remarks>
/// Deliberately just the three fields the protocol needs. Whose device this is, when it was registered
/// and what it is allowed to be told are the consumer's questions, kept in the consumer's own table —
/// this package holds no state and would only be able to answer them wrongly.
/// </remarks>
/// <param name="Endpoint">The push service URL the browser was given. Must be absolute https.</param>
/// <param name="P256dh">The subscription's public key, base64url.</param>
/// <param name="Auth">The subscription's auth secret, base64url.</param>
public sealed record PushSubscription(string Endpoint, string P256dh, string Auth);

/// <summary>
/// Posts one encrypted message to one push endpoint (RFC 8030 delivery, RFC 8291 body, RFC 8292 auth).
/// </summary>
/// <remarks>
/// <b>It logs nothing.</b> Every failure comes back in <see cref="PushResult"/> with the push service's
/// own detail, and the caller logs it — the caller is the only side that knows whose device it was and
/// whether losing it matters.
/// </remarks>
public sealed class WebPushSender(HttpClient http)
{
    /// <summary>How long the push service should hold the message for a device that is offline. Four
    /// hours: a crash notification is worth catching up on after a nap, worthless after a workday.</summary>
    private const int TtlSeconds = 4 * 60 * 60;

    public async Task<PushResult> SendAsync(
        PushSubscription sub, byte[] payload, VapidKeyPair keys, string subject, CancellationToken ct)
    {
        if (!Uri.TryCreate(sub.Endpoint, UriKind.Absolute, out Uri? endpoint)
            || endpoint.Scheme != Uri.UriSchemeHttps)
            return new PushResult(PushOutcome.Expired, null, "endpoint is not an absolute https URL");

        byte[] body;
        try
        {
            body = WebPushCrypto.Encrypt(
                payload,
                WebPushCrypto.FromBase64Url(sub.P256dh),
                WebPushCrypto.FromBase64Url(sub.Auth));
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            // The stored keys are malformed — no retry will fix that, so retire the row rather than
            // failing against it forever.
            return new PushResult(PushOutcome.Expired, null, "subscription keys are unusable: " + ex.Message);
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new ByteArrayContent(body);
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        req.Content.Headers.ContentEncoding.Add("aes128gcm");
        req.Headers.TryAddWithoutValidation("TTL", TtlSeconds.ToString());
        // "Urgency: normal" is the default; left unset rather than restated.
        req.Headers.TryAddWithoutValidation(
            "Authorization", VapidSigner.Authorization(keys, endpoint, subject, DateTimeOffset.UtcNow));

        HttpResponseMessage res;
        try
        {
            res = await http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return new PushResult(PushOutcome.Failed, null, ex.Message);
        }

        using (res)
        {
            int status = (int)res.StatusCode;
            if (res.IsSuccessStatusCode)
                return new PushResult(PushOutcome.Accepted, status, null);

            // 404/410 is the push service saying this subscription no longer exists — the browser
            // unsubscribed, cleared its data, or the service rotated it. It is the ONLY answer that
            // means "delete"; treating anything else that way would evict a device over a bad minute.
            if (res.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone)
                return new PushResult(PushOutcome.Expired, status, "subscription no longer exists");

            // The push service's own words, capped — a caller reporting a failure should be able to
            // quote the reason rather than paraphrase it.
            string detail = await SafeReadAsync(res, ct).ConfigureAwait(false);
            return new PushResult(PushOutcome.Failed, status, detail);
        }
    }

    private static async Task<string> SafeReadAsync(HttpResponseMessage res, CancellationToken ct)
    {
        try
        {
            string s = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return s.Length > 300 ? s[..300] : s;
        }
        catch { return res.ReasonPhrase ?? ""; }
    }
}
